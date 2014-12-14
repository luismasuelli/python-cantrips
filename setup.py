from distutils.core import setup

setup(
    name='python-cantrips',
    version='0.1',
    packages=['cantrips', 'cantrips.watch'],
    url='https://github.com/luismasuelli/python-cantrips',
    license='LGPL',
    author='Luis Masuelli',
    author_email='luismasuelli@hotmail.com',
    description='Python library with quick utilities to make use of in a wide variety of situations',
    install_requires=['future>=0.14.2', 'six>=1.7.3']
)