from setuptools import setup


setup(
    name='gentlskey',
    install_requires=[
        'click'],
    entry_points={
        'console_scripts': ['gentlskey = gentlskey:main']},
    pyackages=['gentlskey'])
