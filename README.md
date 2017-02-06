Drvperf is a console utility to measure various characteristics of mass storage
devices and mass storage subsystem as a whole in Linux environment.
It is supplementary to the article 
[Storage subsystem performance: analysis and recipes](https://andreigudkov.github.io/sspar/), 2016.

It includes following common and exotic tests:

 * sequential access performance [MB/s]
 * random access performance [IOPS, ms]
 * (SSD/RAID) determine optimal concurrency factor
 * (HDD) determine empirically fullstroke seek time [ms] and rotationl speed [RPM]
 * (HDD) determine empirically track-to-track seek time [ms] and rotational speed [RPM]

Full description is provided by manual page: `$ man -l drvperf.1`

Build steps:

    $ mkdir build
    $ cd build
    $ cmake -DCMAKE_BUILD_TYPE=Release ..
    $ make
    $ ./drvperf --help

