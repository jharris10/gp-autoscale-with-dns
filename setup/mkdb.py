import boto3
from netaddr import IPNetwork
import logging
from botocore.exceptions import ClientError
import argparse
import re

tablename =''
dynamodb = ''
region = ''
gwMgmtIp = ''




def put_item(IP, Pool, IntIP):
    table = dynamodb.Table(tablename)

    try:
        table.put_item(
        Item={
            'TunnelIP': IntIP,
            'IP': IP,
            'Pool Range': Pool,
            'Allocated': 'no'
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])


def create_db(network, netmask):
    ip = IPNetwork(network)

    TunnelIPs = ip
    ip = IPNetwork(network)
    subnets = list(ip.subnet(netmask,count=20))
    i=len(subnets)
    for i in range(len(subnets)):
        subnet = subnets[i]
        prefix = str(subnets[i].prefixlen)
        ip_list = list(subnet)
        num_of_ips = len(ip_list)
        first_usable = str(ip_list[2])
        last_usable = str(ip_list[-2])
        pool_addresses = "" + first_usable + "-" + last_usable + ""
        subnettxt = str(subnet)
        TunnelIPtxt = ""+ str(ip_list[1])
        put_item(subnettxt, pool_addresses, TunnelIPtxt)


def init_clients(keys_path):
    """Initialize clients."""
    access_key = ''
    secret_key = ''

    if keys_path:
        with open(keys_path, 'r') as fkeys:
            keys = fkeys.read()
            try:
                access_key = re.search(r'aws_access_key_id = ([^\n]+)', keys, re.I).group(1)
                secret_key = re.search(r'aws_secret_access_key = ([^\n]+)', keys, re.I).group(1)
            except AttributeError:
                raise ValueError('Credentials are not in the right format. '
                                 'The expected format is:\naws_access_key_id=XXXX\naws_secret_access_key=XXXX')
            dynamodbhandle = boto3.resource('dynamodb', region_name=region, aws_access_key_id=access_key,
                                      aws_secret_access_key=secret_key)
            return dynamodbhandle





def main():
    global region
    global dynamodb
    global tablename
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--cidr_network', help = "Supernet of Pool Address space 192.168.0.0/16",type=str)
    parser.add_argument('-m', '--subnetmask', help ='Netmaks for pool address range for each gateway "25"',type=int)
    parser.add_argument('-t', '--tablename', default="GPClientIP", help = "DynamoDB table name",type=str)
    parser.add_argument('-r', '--region', help = "Region", default='us-west-2', type=str)


    args = parser.parse_args()
    region = args.region
    dynamodb = init_clients("/Users/jharris/.aws/credentials")
    tablename = args.tablename

    print (args.cidr_network)
    print (args.subnetmask)
    create_db(args.cidr_network, args.subnetmask)


if __name__ == "__main__":
    main()