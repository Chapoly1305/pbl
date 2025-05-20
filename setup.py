from setuptools import setup

setup(
    name="pbl_dat_dump",
    version="1.0.0",
    description="Python utility to dump PBL database files",
    author="Chapoly1305",
    py_modules=["pbl_dat_dump"],
    entry_points={
        "console_scripts": [
            "pbl_dat_dump=pbl_dat_dump:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)