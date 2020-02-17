# Notes on Python

This should give a decent rundown of the python language for anyone who is familiar
with programming constructs. At the very least it provides a good starting point
for exploring the finer points of the language. I am by no means a python expert
and this doc was written during my own personal investigation. You will find
this document to be more of a reference, additional reading will be required
to learn the details.

NOTES:

  I try to identify Python 2.7 differences and use only Python 3 examples but
  my sources are mixed and something my slip by. I will do my best to update
  mistakes as I identify them.

  This link should highlight some major differences if there are concerns:
  https://sebastianraschka.com/Articles/2014_python_2_3_key_diff.html#raising-exceptions

  This link should give a decent discussion of the topics covered here:
  https://thomas-cokelaer.info/tutorials/python/index.html
  Take care about the python 2 vs 3 discrepancy though.

## Preliminaries

1. **pip3**

    This is for managing python packages. Although python does recommend using
    your distro's repos for this because they are already compat tested. 

    * Install
      `sudo apt install pip3`

    * Syntax
      `pip3 <command> [options]`

    * commands: install, download, uninstall, list, show, check, search

2. **pipenv**

    This is for managing python environments on a per project basis. So one project
    can use version 1.X of a lib while another uses 4.X.

    * Install

    `pip3 install --user pipenv`

    * Creating a virtual Env

    This is how you configure a project to utilize a virtual environment through pipenv:

    `cd project_folder`
    `pipenv install <package>`

    This will automatically set up a venv with "<package>" installed. If you don't specify
    a package, it will simply create the environment and Pipfile. It is not possible
    to name the environemnt yourself as pipenv needs the directory structure to keep
    track.

    * Notes

    If you're working in a venv, you should no longer use `pip install` but prefer
    `pipenv install` (same for other commands) to avoid doing things on a global level
    when you intend them for the venv.

    pipenv's `Pipfile` is intended to replace pip's `requirements.txt` as the project's
    package list.

    `pipenv shell` will give you a new shell with the environment activated so you can
    run your project without worrying about globally installed packages.

    Use the --dev flag to install a package only for development purpose.
    ex. `pipenv install pytest --dev`. Use the `lock` command to update your production
    build file (Pipfile.lock) with the Pipfile you currently have.

3. **Vim Settings**

    If you, like me, are a fan of vim. You'll know what to do with this. It makes sure
    you're following the PEP8 whitespacing guidelines for python.

        " PYTHON whitespace
        autocmd Filetype python setlocal expandtab
          \ | setlocal shiftround
          \ | setlocal textwidth=79
          \ | setlocal shiftwidth=4
          \ | setlocal tabstop=4
          \ | setlocal softtabstop=4
          \ | setlocal autoindent
        let python_highlight_all = 1
 
4. **Python Project Architecture**

    See: http://as.ynchrono.us/2007/12/filesystem-structure-of-python-project_21.html

    Similar to other coding endeavors. here's a template:

        /project_name/
          |
          |- README.md        # Project information
          |- LICENSE          # Legal 
          |- setup.py         # Python setup/install script
          |- equirements.txt  # (or Pipfile)
          |- bin/             # Scripts/usage. NO file ext.
          |- doc/             # Detailed Documentation folder
          |- package_name/  # Source files for a package of your poject
            |
            |- package.py
            |- __init__.py
            |
            |- test/          # Unit tests for package
              |
              |- test_package.py
              |- __init__.py

    Be cautious about the following architecture mistakes:
    * Circular dependencies (on imports)
    * Over coupling (changing a class' implementation breaks another class')
    * Reliance on globals
    * Spaghetti code. Hard to maintain due to python's indenting
    * Over classification creating extreme class/file bloat.

5. **Naming Conventions**

    Avoid using " ", ".", "-", "_" in file names as they can have unintended effects.

6. **Importing**

    (importing should remind the reader of the `using` keyword in C and should
    be treated similarly)

    Avoid using the following as it makes the code's intentions unclear and could
    clobber your namespace:

        from mymod import *


    Importing single functions is less offensive because it is clear what function
    is intended for use, but it still removes the namespace.

        from mymod import myfunc


    The ideal way is importing the module and accessing the imported items via namespace:

        import mymod
        x = mymod.myfunc()


    Finally, if the namespaces are very deep, one may use:

        import mymod.sub1.sub2.deepmod as mod

7. **Packages**

    A directory with an `__init__.py` file in it is considered a python package 
    (collection of modules). It typically contains all package-wide definitions.
    import modules from a package with:

        `import mypackage.mymod`

    This will look for `mypackage``s __init__.py` and execute it, then look for
    mymod.py. This should be kept in mind when creating many layers of sub-modules.
    It is perfectly acceptable to have an empty `__init__.py` file if the modules
    are completely independant

8. **Noteworthy Standard Modules**

    - dmb         - databases
    - cpoy        - shallow/deep copy
    - os,sys,path - Tools for files/paths/dirs/process/env/etc.
    - string      - additional string manipulation
    - time        - Various time/date operations
    - thread      - threading (or what counts as threading in python)
    - pickle      - serializing/object storage
    - md5,sha     - hashing/crypto
    - type        - identifying/comparing object types
    - random      - if you need random numbers

9. **Useful Libs**

    - matplotlib  - Plotting
    - numpy       - array/mats
    - scipy       - numerical analysis
    - tkinter     - gui
    - igraph      - graphing

10. **Documentation**

    Doxygen supports python if you are familiar with that framework. Use `##` in 
    place of `/**`. It may also help to turn on the `OPTIMIZE_OUTPUT_JAVA` in your doxyfile.
    http://www.doxygen.nl/

    Sphinx is a more accepted python documentation method however.
    https://www.sphinx-doc.org/en/master/

11. **NOTES**

    * In Python, _everything_ is an object

    * Functions are first class objects. Meaning they can be passed around and used
      as arguments. The `@` symbol is used to create decorators. 

    * Python makes use of decorators. Decorators are functions that extend the
      behavior of other functions without directly modifying them.

    * Due to Global Interpreter Lock (GIL) python is generally not considered the best
      at utilizing threading.

## Python Features and Syntax

* **Basic Data Structures**

    - Lists: [ 1, 2, "a", "b" ]

        Lists can be accessed backwards using `lst[-1]` this will circle around to the back

    - Tuples: ( 1, 2, "a", "b" )

        immutable, very fast

        two methods: .index('value'), .count('value')

        Unpacking: x, y, z = (1, 2, 3)

    - Dicts: d = { "a":1, "b":2 }

        Not sorted. Contains key value pairs. no Duplicate keys. No order

        d.keys() # "a", "b"

        d.values() # 1, 2

        d["a"] # 1

        .items(), .has_key('key'), .get('key'), .pop('key'), .pipitem(), .clear(), .del('a')
        .itervalues(), .iterkeys(), .iteritems()

    - Strings: "1 2 a b"

        immutable

        escape char = `\`, unicode char = "\u0041", docstrings = "\textbf{}"

        `str.count( 'substring' )`, `len( str )`

    - Sets: set( [1, 2, 3, 4] ) # no duplicates

        Union |, Intersection &, Subset <, Difference -, Symmetric Diff ^

        copy method `b = a.copy()`

    - Frozensets  frozenset( [1, 2, 3, 4] )

        immutable version of `set`

        May not contain other sets (immutability)

        Can be used as dict keys (as opposed to `set`) ex. `fa = {frozenset([1, 2]): 1}


* **Single, double, triple quotes & strings**

    - `\` is the escape character
    - You can use double quotes within a single quoted string and vice versa (like bash)
    - One may use `'''` or `"""` around strings to allow the use of single and double
      quotes withing. However, if the string starts or ends with a single or double
      quote, one must use the opposite triple quote. Ex:
        `"""I said, "Don't touch that""""` will result in an error, instead use
        `'''I said, "Don't touch that"'''`
    - Triple quotes may be used to create multi line strings with `\n` chars
    - One may use the `#` symbol within triple quotes


* **String formatting:**
    1. %-formatting (not recommended)

            name = "Steve"
            age = 33
            "Hello, %s. You are %s." % (name, age)

    2. str.format()
    Easier to read than %-formatting. Still a bit verbose

            # Ex. 1
            "Hello, {}. You are {}.".format(name, age)

            # Ex. 2 - Variable Reference
            "Hello, {0}. You are {1}.".format(name, age)

            # Ex. 3 - Variable Subs
            person = {'name': 'Eric', 'age': 33 }
            "Hello, {name}. You are {age}.".format(name=person['name'], age=person['33'])

            # Ex. 4 - Dictionary Expansion
            person = {'name': 'Eric', 'age': 33 }
            "Hello, {name}. You are {age}.".format(**person)

    3. f-strings

            # Ex. 1 - Variable Substitution
            name = "Steve"
            age = 33
            f"Hello, {name}. You are {age}." # Can use capital letter F as well

            # Ex. 2 - Arithmetic
            f"{2 * 3}" # Prints '6'

            # Ex. 3 - functions
            def to_lowercase( input ):
                return input.lower()

            name = "Steve Jobs"
            f"{to_lowercase(name)} is worshipped like a god." # fn will be evaluated

            # Ex. 4 - Methods
            f"{name.lower(name)} is worshipped like a god." # fn will be evaluated

            # Ex. 5 - Multiline
            message = (
                f"Hello, {name}. "
                f"You are {age}."
            )
            message # will print the message as a single line, properly formatted

            # There is, of course, more to this

* **Object Represenation**

  Objects can have methods which allow them to represented as other objects, such
  as strings. See `__str__()` and `__repr__()` methods


* **Functions**
    - Basic

            def myfunction( var1, var2 )
                # Do Something

    - Functions can have default values:

            def myfunction3( a, b, c=1 )
                return a+b+c
            
            mufunction3( 3, 4 ) # Will succeed

    - functions can use positional and keyword arguments. Positional are self-explanatory
      keyword arguments are directly specified

            myfunction( 2, 3 )            # Positional
            myfunction( var1=2, var2=3 )  # Keyword


    - Functions can accept any number of positional arguments plus keyword arguments.
      The positional arguments are brought in as a tuple. 

            def myfunction2( *numbers, initial )
                for n in numbers:
                    total += n
                return total

            myfunction2( 1, 2, 3, 4 ) # Will fail because initial has not been specified
            myfunction2( 1, 2, 3, 4, initial=1 ) # Will succeed


    - Functions can be keyword only without the unlimited positional args ( * operator )

            def myfunction4( var1, var2, *, var3=None, var4=None )

            myfunction4( var1=2, var2=5 )

      All arguments after `*` must be specified by keyword (yet they do have default
      values so they don't need to be specified at all), the ones before can
      be specified positionally.       

    - Functions may capture any keyword arguments provided to them with the `**`
      operator:

            def format_attributes( **attributes )

            format_attributes( name="Steve", age=33, color="Purple" )

    - The following function will accept any number of positional and any number
      of keyword arguments

            def myfunc5( *args, **kargs )


* **Underscore**

    The underscore is a special character in python. Here are some uses
    - storing the value of the last expression in the interpreter
    - Ignoring specific values (don't care). In for loops, in unpacking tuples, etc.
    - Leading underscores on function/method/var names are for private variables.
      These are ignored by `import *`
    - Trailing underscores can be used to prevent conflicts with python built-ins
    - Double underscores will prompt the interpreter to "mangle" a classes attributles
      by inserting the class name between the `__` behind the scenes.
    - Double leading and trailing underscores are for "magic methods"


* **List Comprehension**

    This is a way of generating lists from a for loop. Very handy and almost ubiquitous

        return [ y for y in lst if len(y) > 5 ] # return a list containing all entries in `lst`
                                                # that are greater than 5
    


* **Dict Comprehension**

      # Of the form:
      return { k:v for (k,v) in iterable }

      # Ex.
      myDict = { x:x**2 for x in [1, 2, 3, 4, 5] }

      # Ex.
      myDict = { x:x**3 for x in range(10) if x**3 % 4 == 0 ) # { 0:0, 2:8, 4:64, 6:216, 8:512 }

* **Set Comprehension**

      # Ex.
      {s for s in [ 1, 2, 1, 0 ] } # set( [0, 1, 2] )


* **Iterators**

    Objects through which you can traverse all the elements. 
    `iter()` can be used to convert items to iterator.


* **Generators and Yield**

    - Generators calculate a series of results one-by-one on demand, they can be used like `list`.
    - Because they are on-demand, generators do not have a length.
    - Useful for memory intensive tasks since they generate on-demand instead of having all elements
      instantiated.
    - Generators are created like list comprehensions, except they use `()` instead of `[]`
      `generator = ( x+x for x in range(3) )`

    - The `yield` keyword returns a generator. a generator must be executed with `next(mygen)`
      in order for it to return the next available result. To clarify, say you define a function
      the searches a file for a keyword than yeilds the line with a match. You would create the
      generator: `gen = search(keyword,file)` then execute it for the first result: `next(gen)`
      then call `next(gen)` for the following result. If it finds no more results, it throws
      a StopIteration exception

    - In python 2.X generators had a `.next()` method. This is no longer the case in 3

          # Fibonacci Example
          def fibonacci( n ):
              curr = 1
              prev = 0
              counter = 0
              while counter < n:
                  yield curr
                  prev, curr = curr, prev + curr
                  counter += 1

          fib = fibonacci( 4 )
          print( next(fib) ) # 1
          print( next(fib) ) # 1
          print( next(fib) ) # 2
          print( next(fib) ) # 3
          print( next(fib) ) # StopIteration Exception
    
* **Enumeration**

    Often you will run into a situation where you are incrementing a counter during a loop, 
    using an enumeration is considered more pythonic.

        ```py
        # Without enumeration
        x = [ "cat", "dog", "bear", "mouse" ]
        count = 0
        for y in x:
            print( y )
            count += 1

        print( "how many animals are there?" )
        print( count )

        # with enumeration
        print( "\n\n" )
        x = [ "cat", "dog", "bear", "mouse" ]
        for count, y in enumerate( x, 1 ):
            print( f"{count}, {y}" )

        print( "how many animals are there?" )
        print( count )
        ```

* **Increment/Decremenet**

    The `++` and `--` operators do not exist in python. There are generally better ways to
    perform this operation. 

    `+=` and `-=` do exist however

* **Passing Arguments**

    Passing arguments is done by value for simple types and by reference for objects. You
    can NOT pass an object by value.

## Python Basics

* **Numeric Types -- int, float, long, complex**

    - `bool` is a subtype of `int`
    - `int` is equivalent to a `long` in C. They have at least 32 bits
    - `float` is a `double` in C.
    - `long` are forced by appending `L` to the number. Plain ints are converted automatically
      if they are big enough to require.
    - For complex number, use `j` or `J` or `complex(real,imag) to denote. To extract from complex 
      number `z`, use z.real and z.imag 
    - Using a number without a `.` creates an integer and will need to be cast to float if you
      want to do float point operations `float()`
    - Mixed arithmetic is supported! The narrower type will always be converted to the wider type
      int < long < float. In python 2.x, however, one needed to take care about mixing floats and
      ints. Int division in 2.x would perform a floor division by default
    - Numbers can be cast using `int()`, `long()`, `float()`

* **Variables**

    - `global` keyword to use global variables within functions. Variables don't get defined
      as global like they are in C. In Python, global/config variables can be placed in
      a `config.py` file then imported with `import config`
    - `nonlocal` is used in nested functions to refer to variables layers up in the nest

* **Useful Functions**

    - print( )
    - len( )
    - range(start,stop.step)
    - xrange() # 2.7 ONLY. xrange is a generator object good for BIG ranges
    - type()
    - f = open(filename, 'r')

* **Flow Control**

    The control keywords cannot have nothing to execute. Use `pass` keyword if you want to leave
    an `else:` blank, for example.

    - For Loop

          for x in y:
              print( x )
          else:     # rarely use, gets executed at the end
              print( "done" )

    - If statements

          if x > 0:
            pass
          elif x = 0:
            pass
          else:
            pass

    - While Loop

          x = 0
          while( x < 100 ):
              x += (x+1)**2
              if x > 100:
                  break

    - Do-While Loop

      Does not exist in python

* **Functions**

    - General

          def myFunc( *args, **kargs )
              """Title (Docstring)
              Function information
              """
              return x, y, z

          # Retrieve docstring with
          print( f"{myFunc.__doc__}" )

          # Attribute Retrieval for Functions
          print( f"{myFunc.__name__}" )

          # Attribute Retrieval for Functions
          print( f"{myFunc.__module__}" )
  
    - Lambda (Anonymous) Functions

          from math import pi, sqrt
          f = lambda r: pi * r * r
          f( sqrt( 1./pi ) )

          # multiple params
          f2 - lambda x,y: return x**y


      There are several functions which can be useful in the context of lambda functions:

      zip()

      reduce()

      filter()  - Often replaced by list comprehension

      map()     - Often replaced by list comprehension


* **Exceptions**

    - python suppots try/catch like functionality

          try:
              1/0
          except ZeroDivisionError as e: # different in Python 2.x
              print( 'Can't divide by zero' )
              print( e )  # The system ZeroDivisionError
          except e:
              print( 'Catch everything else' )
          finally:
              print( 'Always executes after the try/except. Can do clean up like close open files' )
          else:
              print( ' This is executed if the try block succeeded ' )

    - You can throw your own exceptions with `raise <ExceptionType>("Custom Desc.")`. Excpetion
      type include: Exception, AssertionError, AttributeError, KeyError, MemoryError, 
      KeyboardInterrupt, RuntimeError, StopIteration. There are many more.
      See the following link for exception hierarchy:
      https://docs.python.org/3/library/exceptions.html#exception-hierarchy

    - You can make user defined exceptions that inerit from the `Exception` class:

          class Error(Exception):
              """Base class for exceptions"""
              pass
          class InputError(Error):
              """Exception for input errors"""
              def __init__(self, expression, message):
              self.expression = expression
              self.message = message

* **Assert**

    The ever useful `assert` keyword exists in python. Exceptions should be preferred however
    to help with optimization.

          age = -1
          assert age 0 < age < 100, 'Come on, you can't be that old'

* **Classes**

    - Standard definition. 

      There are no true private variables as they can be accessed externally.
      a `_` in front conveys the idea that you want it to be private though. Note that, in Python 2,
      all classes should inherit `object`. This is not necessary in Python 3 unless backward
      compatability is desired. For further reading, look for `new classes vs old classes`

          class MyClass( object ):
              # Class variables
              counter = 0

              # member fn
              def __init__( self, name, num ): # constructor
                  self.name = name  # Instance Variable

              def __del__( self ): # destructor, not needed that often due to garbage collection
                  print( "Deleting object" )

              def a_method( self ):
                  print( 'Hello' )

              def __str__( self ):
                  return( f"There are {self.counter} instances" )
              
    - Class vs Instance variables

      Variables defined at the class level are similar to static variables in C++, all instances
      of a class have access to them. Variables defined at the instance level `self.var` are 
      specific to the instance. Do not attempt to change class variables using instance access
      `a.classvar1 = "steve"` as this will create an instance variable for `a` which overrides
      the class variable. Instead, one should access using the class name 
      `MyClass.classvar1 = "Steve"`

    - Overloading 

        - Constructors

          Behave more like initializers. You cannot overload them as you can in C++. Instead, use
          a combination of variable number of arguments `def __init(self, *args, **kargs)`, magic
          word `None`, and `if...else` to achieve the desired functionality.

        - Functions

          Same as constructors, there is c++ style overloading.

        - Built-in

          These can be overloading by defining a function overwriting the magic name like `__len__`
          this will define the behavior of `len()` when called on your object.

        - Operators

          These can also be overloaded in a manner similar to built-ins: `__add__`, `__sub__`, __lt__`
    
    - Inheritance

      Multiple inheritance is possible with a comma separated list. Special care should be
      take to avoid "diamond inheritance" although python is certainly better at handling 
      this situation tha C++ is

          class Tree( object ):
              def __init__( self, name ):
                  self.name = name

              def __str__( self ):
                  return "name: " + self.name

          class FruitTree( Tree ):
              def __init__( self, name, fruit_size ):
                  super


    - Polymorphism

      Python is implicitly polymorphic so the type overload style of C++ is not needed.

    - Class Decorators 

      see the following link for a thorough explaination of decorators:
      https://realpython.com/primer-on-python-decorators/#syntactic-sugar

      The three main built-in class decorators are: 

      "@classmethod" To define methods in a class namespace that are not connected to an instance

      "@staticmethod" To define methods in a class namespace that are not connected to an instance

      "@property" To customize getters and setters for class attributes

      `@singleton` is a decorator for the class itself that allows only one instance of a class


## References







