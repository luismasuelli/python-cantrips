from setuptools import setup, find_packages

setup(
    name='python-cantrips',
    version='0.7.0',
    namespace_packages=['cantrips'],
    packages=find_packages(),
    url='https://github.com/luismasuelli/python-cantrips',
    license='LGPL',
    author='Luis y Anita',
    author_email='luismasuelli@hotmail.com',
    description='Python library with quick utilities to make use of in a wide variety of situations',
    install_requires=['future>=0.14.2']
)