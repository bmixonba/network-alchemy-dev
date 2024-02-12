# Overview

This directory contains formal models for the various attacks. Each attack has 2 versions of the code, one vulnerable and one fixed. 

The models replicate the behaviour of an actual VPN server-client setup.
The vulnerable version is susceptible to the corresponding attack while the fixed ones are the modified versions of the functionality that we propose to fix the vulnerability. 

## Running code

This code requires using the TLA+ toolkit. It can be found at https://lamport.azurewebsites.net/tla/toolbox.html.
Follow the instructions there to get the system working.

# Formal Model Setup

This section will detail how to setup the formal models after you have downloaded and installed TLA+ Toolkit.

The general setup remains the same for the attacks. However, the invariants are different for each attack.

The common steps are detailed below.
1. Open up the `.tla` file of interest in the TLA+ Toolbox.
2. On the left side, right-click on `models` and select `New Model`. Name the model and create it.
3. Expand the `Invariants` section and choose to add a new invariant.
4. The invariant to be added varies for each attack.
5. Click the green play button at the top to start model checking.
6. Allow the model checking to complete and the verify if invariant is violated or not.
## ATIP

Add the following invariant for the ATIP attack.
```
ATIPInv=FALSE
```
## Eviction Reroute

Add the following invariant for the Eviction Reroute attack.
```
EvictionReroute=FALSE
```