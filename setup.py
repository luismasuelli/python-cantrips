from distutils.core import setup

setup(
    name='python-cantrips',
    version='0.5.0',
    packages=['cantrips',
              'cantrips.watch',
              'cantrips.types',
              'cantrips.patterns',
              'cantrips.protocol',
              'cantrips.protocol.tornado',
              'cantrips.protocol.twisted',
              'cantrips.task'],
    url='https://github.com/luismasuelli/python-cantrips',
    license='LGPL',
    author='Luis Masuelli',
    author_email='luismasuelli@hotmail.com',
    description='Python library with quick utilities to make use of in a wide variety of situations',
    install_requires=['future>=0.14.2']
)