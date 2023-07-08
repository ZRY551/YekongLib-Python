from setuptools import setup

setup(
    name='YekongLib',
    version='1.1.1',
    author='YELANDAOKONG',
    author_email='yelandaokong@yldk.xyz',
    description='A Python library',
    long_description='A Python library.',
    long_description_content_type='text/markdown',
    url='https://github.com/ZRY551/YekongLib-Python',
    packages=['YekongLib'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=['pycryptodome'], # Add this line to specify the dependency
)

