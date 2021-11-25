# coding: utf-8
__doc__ = """
pdict has a dictionary like interface and a sqlite backend
It uses pickle to store Python objects and strings, which are then compressed
Multithreading is supported
"""

import datetime
import sqlite3
import zlib
import md5
import time
try:
    import cPickle as pickle
except ImportError:
    import pickle
try:
    import pymongo
    import bson.binary
except ImportError:
    pymongo = None

DEFAULT_TIMEOUT = 10000
# between 1-9 (in my test levels 1-3 produced a 1300kb file in ~7 seconds while 4-9 a 288kb file in ~9 seconds)
COMPRESS_LEVEL = 6



class PersistentDict:
    """Stores and retrieves persistent data through a dict-like interface
    Data is stored compressed on disk using sqlite3 

    filename: 
        where to store sqlite database. Uses in memory by default.
    expires: 
        a timedelta object of how old data can be before expires. By default is set to None to disable.
    timeout: 
        how long should a thread wait for sqlite to be ready (in ms)
    isolation_level: 
        None for autocommit or else 'DEFERRED' / 'IMMEDIATE' / 'EXCLUSIVE'
    num_caches:
        how many cache database(SQLite) files to be used
    use_md5hash
        if False will use hash() of the key to decide the sqlite file index. if False will use md5 hash instead.
    >>> filename = 'cache.db'
    >>> cache = PersistentDict(filename)
    >>> url = 'http://google.com/abc'
    >>> html = '<html>abc</html>'
    >>>
    >>> url in cache
    False
    >>> cache[url] = html
    >>> url in cache
    True
    >>> cache[url] == html
    True
    >>> cache.get(url)['value'] == html
    True
    >>> cache.meta(url)
    {}
    >>> cache.meta(url, 'meta')
    >>> cache.meta(url)
    'meta'
    >>> del cache[url]
    >>> url in cache
    False
    >>> os.remove(filename)
    """
    def __init__(self, filename='cache.db', expires=None, timeout=DEFAULT_TIMEOUT, isolation_level=None, num_caches=1, use_md5hash=False):
        """initialize a new PersistentDict with the specified database file.
        """
        self.filename = filename
        self.expires, self.timeout, self.isolation_level, self.num_caches, self.use_md5hash = \
            expires, timeout, isolation_level, num_caches, use_md5hash
        for i in range(num_caches):
            conn = self.get_connection(i)
            sql = """
            CREATE TABLE IF NOT EXISTS config (
                key TEXT NOT NULL PRIMARY KEY UNIQUE,
                value BLOB,
                meta BLOB,
                status INTEGER,
                updated timestamp DEFAULT (datetime('now', 'localtime'))
            );
            """
            conn.execute(sql)
            conn.execute("CREATE INDEX IF NOT EXISTS keys ON config (key);")


    def __copy__(self):
        """make a copy of current cache settings
        """
        return PersistentDict(filename=self.filename, expires=self.expires, 
                              timeout=self.timeout, isolation_level=self.isolation_level, num_caches=self.num_caches)


    def __contains__(self, key):
        """check the database to see if a key exists
        """
        conn = self.get_connection(key)
        row = conn.execute("SELECT updated FROM config WHERE key=?;", (key,)).fetchone()
        return row and self.is_fresh(row[0])
   

    def __iter__(self):
        """iterate each key in the database
        """
        for i in range(self.num_caches):
            conn = self.get_connection(i)        
            c = conn.cursor()
            c.execute("SELECT key FROM config;")
            for row in c:
                yield row[0]

    def __getitem__(self, key):
        """return the value of the specified key or raise KeyError if not found
        """
        conn = self.get_connection(key)
        row = conn.execute("SELECT value, updated FROM config WHERE key=?;", (key,)).fetchone()
        if row:
            if self.is_fresh(row[1]):
                value = row[0]
                return self.deserialize(value)
            else:
                raise KeyError("Key `%s' is stale" % key)
        else:
            raise KeyError("Key `%s' does not exist" % key)


    def __delitem__(self, key):
        """remove the specifed value from the database
        """
        conn = self.get_connection(key)
        conn.execute("DELETE FROM config WHERE key=?;", (key,))


    def __setitem__(self, key, value):
        """set the value of the specified key
        """
        updated = datetime.datetime.now()
        conn = self.get_connection(key)
        conn.execute("INSERT OR REPLACE INTO config (key, value, meta, updated) VALUES(?, ?, ?, ?);", (
            key, self.serialize(value), self.serialize({}), updated)
        )


    def get_connection(self, key):
        """Return sqlite connection for this key
        Multiple sqlite connections are supported to minimize the write bottleneck
        """
        #XXX
        if self.num_caches == 1:
            filename = self.filename
        else:
            if isinstance(key, int):
                conn_i = key
            else:
                # map hash remainder to sqlite index
                if not self.use_md5hash:
                    conn_i = hash(key) % self.num_caches
                else:
                    hashvalue = md5.md5(key).hexdigest()
                    conn_i = (ord(hashvalue[0]) + ord(hashvalue[-1])) % self.num_caches
            filename = '%s.%d' % (self.filename, conn_i)
        conn = sqlite3.connect(filename, timeout=self.timeout, isolation_level=self.isolation_level, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        conn.text_factory = lambda x: unicode(x, 'utf-8', 'replace')
        return conn


    def serialize(self, value):
        """convert object to a compressed pickled string to save in the db
        """
        return sqlite3.Binary(zlib.compress(pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL), COMPRESS_LEVEL))
    
    def deserialize(self, value):
        """convert compressed pickled string from database back into an object
        """
        if value:
            return pickle.loads(zlib.decompress(value))


    def is_fresh(self, t):
        """returns whether this datetime has expired
        """
        return self.expires is None or datetime.datetime.now() - t < self.expires


    def get(self, key, default=None):
        """Get data at key and return default if not defined
        """
        data = default
        if key:
            conn = self.get_connection(key)
            row = conn.execute("SELECT value, meta, updated FROM config WHERE key=?;", (key,)).fetchone()
            if row:
                value = row[0] 
                data = dict(
                    value=self.deserialize(value),
                    meta=self.deserialize(row[1]),
                    updated=row[2]
                )
        return data


    def meta(self, key, value=None):
        """Get / set meta for this value

        if value is passed then set the meta attribute for this key
        if not then get the existing meta data for this key
        """
        conn = self.get_connection(key)
        if value is None:
            # want to get meta
            row = conn.execute("SELECT meta FROM config WHERE key=?;", (key,)).fetchone()
            if row:
                return self.deserialize(row[0])
            else:
                raise KeyError("Key `%s' does not exist" % key)
        else:
            # want to set meta
            conn.execute("UPDATE config SET meta=?, updated=? WHERE key=?;", (self.serialize(value), datetime.datetime.now(), key))


    def clear(self):
        """Clear all cached data
        """
        conn = self.get_connection(key=None)
        conn.execute("DELETE FROM config;")


    def merge(self, db, override=False):
        """Merge this databases content
        override determines whether to override existing keys
        """
        for key in db.keys():
            if override or key not in self:
                self[key] = db[key]

class MongoCache:
    """Use MongoDB as backend to store cache data
    database_name, collection_name, host, port, username, password:
        MogoDB connection settings
    expires: 
        a timedelta object of how old data can be before expires. By default is set to None to disable.
    """
    
    def __init__(self, database_name, collection_name, host='127.0.0.1', port=27017, username=None, password=None, expires=None):
        self.host, self.port, self.username, self.password, self.database_name, self.collection_name = host, port, username, password, database_name, collection_name
        self.expires = expires
        self.conn = None
        
    def get_connection(self):
        """Connect to MongoDB
        """
        if not self.conn:
            while True:
                try:
                    client = pymongo.MongoClient(host=self.host, port=self.port)
                    db = client[self.database_name]
                    if self.username:
                        db.authenticate(name=self.username, password=self.password)
                    self.conn = db[self.collection_name]
                except Exception, e:
                    print 'Failed to connect to MongoDB: {}'.format(str(e))
                    time.sleep(1)
                else:
                    break
        return self.conn
    
    def safekey(self, key):
        """return a safekey
        """
        if len(key) < 1024:
            return key
        else:
            return md5.md5(key).hexdigest
    
    def is_fresh(self, t):
        """returns whether this datetime has expired
        """
        return self.expires is None or datetime.datetime.now() - t < self.expires
    
    def safe_findone(self, condition, *args, **kwargs):
        """Do find_one() until success, avoid mongodb exception, e.g. connection lost.
        """
        while True:
            try:
                conn = self.get_connection()
                doc = conn.find_one(condition, *args, **kwargs)
            except Exception, e:
                print 'Failed to execute MongoDB find_one command: {}'.format(str(e))
                time.sleep(1)
            else:
                return doc
    

    def __contains__(self, key):
        """check the database to see if a key exists
        """
        doc = self.safe_findone({'_id': self.safekey(key)}, {'updated': True})
        return doc and self.is_fresh(doc['updated'])
    
    def __iter__(self):
        """iterate each key in the database
        """
        conn = self.get_connection()        
        for doc in conn.find({}, {'_id': True}):
            yield doc['_id']   
    
    def __getitem__(self, key):
        """return the value of the specified key or raise KeyError if not found
        """
        doc = self.safe_findone({'_id': self.safekey(key)})
        if doc:
            if self.is_fresh(doc['updated']):
                return self.deserialize(doc['value'])
            else:
                raise KeyError("Key `%s' is stale" % key)
        else:
            raise KeyError("Key `%s' does not exist" % key)

    def __delitem__(self, key):
        """remove the specifed value from the database
        """
        conn = self.get_connection()
        while True:
            try:
                conn.remove({'_id': self.safekey(key)}) 
            except Exception, e:
                print 'Failed to execute MongoDB remove command: {}'.format(str(e))
                time.sleep(1)
            else:
                return True
        
        
    def __setitem__(self, key, value):
        """set the value of the specified key
        """
        updated = datetime.datetime.now()
        conn = self.get_connection()
        key_safe = self.safekey(key)
        doc = {'_id': key_safe, 'value': self.serialize(value) if not value is None else None, 'meta': None, 'updated': updated}
        while True:
            try:
                conn.update({'_id': key_safe}, doc, upsert=True)
            except Exception, e:
                print 'Failed to execute MongoDB update command: {}'.format(str(e))
                time.sleep(1)
            else:
                return True
    

    def get(self, key, default=None):
        """Get data at key and return default if not defined
        """
        data = default
        if key:
            doc = self.safe_findone({'_id': self.safekey(key)})
            if doc:
                data = dict(
                    value=self.deserialize(doc['value']),
                    meta=doc['meta'],
                    updated=doc['updated']
                )
        return data
    
    def meta(self, key, value=None):
        """Get / set meta for this value

        if value is passed then set the meta attribute for this key
        if not then get the existing meta data for this key
        """
        if value is None:
            # want to get meta
            doc = self.safe_findone({'_id': self.safekey(key)}, {'meta': True, 'updated': True})
            if doc:
                return doc['meta']
            else:
                raise KeyError("Key `%s' does not exist" % key)
        else:
            # want to set meta
            conn = self.get_connection()
            while True:
                try:
                    conn.update({'_id': self.safekey(key)}, {'$set': {'meta': value}}, upsert=True)
                except Exception, e:
                    print 'Failed to execute MongoDB update command: {}'.format(str(e))
                    time.sleep(1)
                else:
                    return True                    
            
            
    def clear(self):
        """Clear all cached data
        """
        conn = self.get_connection()
        conn.remove({})
    
    def serialize(self, value):
        """convert object to a compressed pickled string to save in the db
        """
        return bson.binary.Binary(zlib.compress(pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL), COMPRESS_LEVEL))
    
    def deserialize(self, value):
        """convert compressed pickled string from database back into an object
        """
        if value:
            return pickle.loads(zlib.decompress(value))
    

class MongoQueue:
    """MongoDB based queue
    """
    def __init__(self, database_name, collection_name, host='127.0.0.1', port=27017, username=None, password=None):
        self.host, self.port, self.username, self.password, self.database_name, self.collection_name = host, port, username, password, database_name, collection_name
        self.conn = None
        
    def get_connection(self):
        """Connect to MongoDB
        """
        if not self.conn:
            while True:
                try:
                    client = pymongo.MongoClient(host=self.host, port=self.port)
                    db = client[self.database_name]
                    if self.username:
                        db.authenticate(name=self.username, password=self.password)
                    self.conn = db[self.collection_name]
                    self.conn.ensure_index([('priority', pymongo.DESCENDING)])                    
                except Exception, e:
                    print 'Failed to connect to MongoDB: {}'.format(str(e))
                    time.sleep(1)
                else:
                    break
        return self.conn


    def size(self):
        """Total size of the queue
        """
        conn = self.get_connection()
        while True:
            try:
                queue_size = conn.count() 
            except Exception, e:
                print 'Failed to execute MongoDB count command: {}'.format(str(e))
                time.sleep(1)
            else:
                return queue_size
            
    def __len__(self):
        """Total size of the queue
        """
        return self.size()
    
    
    def clear(self):
        """Clear the queue.
        """
        conn = self.get_connection()
        while True:
            try:
                conn.remove({})
            except Exception, e:
                print 'Failed to execute MongoDB count remove: {}'.format(str(e))
                time.sleep(1)
            else:
                return True
            
    def append(self, task, priority=0):
        """Place a task into the queue
        """
        doc = {}
        doc['priority'] = priority
        doc['task'] = task
        doc['updated'] = datetime.datetime.now()
        conn = self.get_connection()
        while True:
            try:
                conn.insert(doc)
            except Exception, e:
                print 'Failed to execute MongoDB update command: {}'.format(str(e))
                time.sleep(1)
            else:
                return True        
    
    def pop(self):
        """Get a task from the queue
        """
        conn = self.get_connection()
        while True:
            try:
                # https://docs.mongodb.com/manual/reference/method/db.collection.findAndModify/
                doc = conn.find_and_modify(query={}, sort=[('priority', pymongo.DESCENDING)], remove=True, limit=1)
            except Exception, e:
                print 'Failed to execute MongoDB find_and_modify command: {}'.format(str(e))
                time.sleep(1)
            else:
                if doc:
                    return doc['task']
                else:
                    raise IndexError('No more task.')