__doc__ = """
Website: 
    https://github.com/kunzhipeng/webscraping
"""

if __name__ == '__main__':
    import doctest
    for name in ['adt', 'alg', 'common', 'download', 'pdict', 'settings']:
        module = __import__(name)
        print name
        print doctest.testmod(module)
