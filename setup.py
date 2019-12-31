from setuptools import setup

setup(name='pyda',
      version='0.1',
      description='Python Decompiler',
      url='https://github.com/ludachrish3/pyda',
      author='Chris Collins',
      author_email='chriscoll93@gmail.com',
      license='MIT',
      packages=[
        'pyda',
        'pyda.binaries',
        'pyda.disassemblers',
        'pyda.disassemblers.x64',
        'pyda.decompilers',
      ],
      test_suite='pytest',  # This might not be right
      tests_require=[
        'pytest',
        'pytest-cov',
      ],
      zip_safe=False)
