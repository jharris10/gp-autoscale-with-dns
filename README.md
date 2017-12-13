# gp-autoscale-with-dns

Here is a CFT and lambda functions to create a Global Protect Infrastructure in AWS that will scale up and down based on demand. 

Directory Sturcture
- Setup
  Contains a python script that will populate a dynamodb database with IP addresses that are allocated to gateways as they are
  created.  The database has an entry for the tunnel interface and the pool of addresses assigned to the GP clients.
- Config_fw 
  Contains the lambda scripts zip file and original script files. 
- Template
  Contains the CFT file for the deployment.


Prerequisties 
  A route53 hosted Domain will need to be created prior to deployment.  We use gw2.gp-autoscale.co.uk in the example documentation
  Dynamodb database
  
