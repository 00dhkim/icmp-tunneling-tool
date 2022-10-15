class Class1(object):
    def __init__(self) -> None:
        print('Class1.__init__')
        self.a = 1
    
class Class2(Class1):
    def __init__(self) -> None:
        print('Class2.__init__')
        # super().__init__()

if __name__ == '__main__':
    c2 = Class2()
    print(c2.a)