#!/usr/bin/env python

import boto3
from pprint import pprint

ec2 = boto3.client('ec2',
                        aws_access_key_id='AAAAAAAAAAAAAA',
                        aws_secret_access_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
all_security_groups = ec2.describe_security_groups()['SecurityGroups']

for security_group in  all_security_groups:
    groupname = security_group['GroupName']
    groupid = security_group['GroupId']
    permissions = security_group['IpPermissions']
    print "##########################################"
    print "Group Name: %s" %(groupname)
    print "Group ID: %s" %(groupid)
    print "Permissions:"
    print "%s %10s %20s" %('PROTO','PORTS','IPRANGE')
    for permission in permissions:
        if permission.has_key('FromPort'):
            fromport = permission['FromPort']
        else:
            fromport = 0
        if permission.has_key('ToPort'):
            toport = permission['ToPort']
        else:
            toport = 0
        ipproto = permission['IpProtocol']
        for ip in permission['IpRanges']:
            for k,v in ip.iteritems():
                print "%s %10s-%s %20s" %(ipproto, fromport, toport, v)
        for user in permission['UserIdGroupPairs']:
            for k,v in user.iteritems():
                if k == 'GroupId':
                    print "%s %10s-%s %20s" %(ipproto, fromport, toport, v)
    print "#########################################"
