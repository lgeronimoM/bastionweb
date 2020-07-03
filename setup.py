 from setuptools import setup, find_packages

setup(
    name='DNS POWER WEB',
    version='1.0',
    Description='DNS web administrator with ansible',
    License='BSD', 
    author='Luis Geronimo',
    author_email='lmgs974@gmail.com',
    long_description=__doc__,
    packages=find_packages(),
    #include_package_data=True,
    zip_safe=False,
)
