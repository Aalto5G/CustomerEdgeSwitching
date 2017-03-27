The directory contains future tasks for improvement.
And few words about test setup

Test Environment: 
	- 'localhost' interface of a Ubuntu16 VM.

Objective:
	- Implementing CETP layering architecture 
	- CES-to-CES and Host-to-Host policy negotiation
	- Integrating PolicyManagement System					[Not implemented yet]


For testing:
	- Run './run_cesa.sh' & './run_cesb.sh' in two separate terminals of a Ubuntu VM. (Emulating CES-A and CES-B)
	- On a third terminal, initiate a DNS A query towards the desired destination and CES-CES and Host-Host CETP policies will be negotiated.

Assumptions:
	- The resolution of DNS queries via DNS Engine is abstracted. And it is assumed that a NAPTR response is somehow available. 
	- The policy for CES and Host are stored in a policy file. 		[The upper limit for some policy elements is stored in 'max_policy']
	- In the next step, the policy file will be replaced by a PolicyManagementSystem, to handle host and CES policies.

CETP protocol:
	- Earlier version of protocol was entirely a Policy Matching protocol. With no negotiation of the acceptable values of each policy element.
	- With a slightly change in the protocol implementation, it can be changed to Policy Negotiation protocol. Where policy elements as well as their values are agreed b/w CES nodes.
	