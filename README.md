# Asyncio CES 
The project aims to implement 2nd version of the Customer Edge Traversal Protocol (CETP), presenting a layered CES/CETP implementation.

## Development environment

The project has been developed in Ubuntu 16.04 environment, using python3, and its 'asyncio' framework for handling asynchronous I/O. The project code has been tested on LXC containers, to similate different network nodes serving corresponding hosts.

## Installing dependencies
<br> apt-get update </br>
<br> apt-get install build-essential python3-dev python3-pip </br>
<br> python3-aiohttp python3-yaml python3-dnspython </br>


## How to Run
For a root user (i.e. sudo), the example command to run CES code is as following:<br>
python3 ces.py config_ces.yaml

Where <i> ces.py </i> is the main python3 file instantiating the CES/CETP functionality; and 'config_ces.yaml' file defines the CES-node specific configurations.

For test purposes, the repo contains two scripts 'run_cesa.sh' and 'run_cesb.sh' to run two CES nodes, i.e. CES-A and CES-B.


## Testing setup
The project code has been tested on LXC containers, connected via default lxcbr0 bridge. The hosts simulated in network of CES-A and CES-B are merely connected to lxcb0 bridge, but default gateway pointing to 'lxcbr0' address on CES-A and CES-B nodes. 

The CES nodes are connected to an additional lxcbr1 bridge as well to simulate an additional available interface at CES. The respective address ranges for both bridges are 10.0.3.xxx/24 and 10.1.3.xxx/24. 

## Caveats
There are three code branches. 
1. The 'master' branch uses local configuration files and cetp policies to run CES code.
2. The 'pms_integration' branch has integrated CES functionality with Policy Management System to leverage user policies on demand.
3. The third branch has some under development ideas, which should improve and simplify implementation.

Besides, the code uses multiple dummy definitions, for example for Host and Interface definitions etc. This iwas done to focus on the implementation of CETP policy negotiation only. In actual/final implementation, the code will leverage proper configuration files.
