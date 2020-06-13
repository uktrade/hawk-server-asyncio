import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='hawk-server-asyncio',
    version='0.0.7',
    author='Department for International Trade',
    author_email='webops@digital.trade.gov.uk',
    description='Utility function to perform the server-side of Hawk authentication',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/uktrade/hawk-server-asyncio',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
    python_requires='>=3.7.0',
    py_modules=[
        'hawkserver',
    ],
    test_suite='test',
    tests_require=[
        'freezegun==0.3.12',
        'mohawk==0.3.4',
    ],
)
