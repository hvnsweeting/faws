# -*- coding: utf-8 -*-
import itertools
import time

import botocore
import boto3

RESOURCES = ('ec2', 'elb', 'sg', 'roles', 'elasticache', 'asg', 'rds')


def request_all(client, funcname, topkey, wait_for=0, **kwargs):
    '''
    Helper function get all result, handle pagination, return list of things
    '''
    paginator = client.get_paginator(funcname)
    all_entities = []

    page_iterator = paginator.paginate(**kwargs)
    for page in page_iterator:
        if wait_for > 0:
            time.sleep(wait_for)
        all_entities.extend(page[topkey])

    return all_entities


def is_running(instance):
    return instance['State']['Name'] == 'running'


def get_all_ec2_instances(filter_predicate=is_running):
    ec2 = boto3.client('ec2')
    all_instances = []
    for reservation in ec2.describe_instances()['Reservations']:
        for instance in reservation['Instances']:
            if filter_predicate(instance):
                all_instances.append(instance)
    return all_instances


def get_all_security_groups():
    ec2 = boto3.client('ec2')
    return ec2.describe_security_groups()['SecurityGroups']


def get_all_volumes():
    ec2 = boto3.client('ec2')
    return ec2.describe_volumes()['Volumes']


def get_all_load_balancers():
    elbc = boto3.client('elb')
    return request_all(elbc, 'describe_load_balancers', 'LoadBalancerDescriptions', PageSize=400)


def get_all_auto_scaling_groups():
    asg = boto3.client('autoscaling')
    return request_all(asg, 'describe_auto_scaling_groups', 'AutoScalingGroups', MaxRecords=100)


def get_all_cache_clusters():
    ec = boto3.client('elasticache')
    return request_all(ec, 'describe_cache_clusters', 'CacheClusters')


def get_all_rds_instances():
    rds = boto3.client('rds')
    return request_all(rds, 'describe_db_instances', 'DBInstances')


def get_all_roles():
    iam = boto3.client('iam')
    return request_all(iam, 'list_roles', 'Roles')


def instance_ids_to_ips(instance_ids):
    # type: List -> Dict[id->ip]
    return


def get_elbs(namefilter=None):
    '''
    Get ELBs and save to global
    '''
    # Use fitler to filter base on elb name
    pass


# TODO design func to get ELB health - related instances
# HOW TO quickly get list of instances that out of service? and/or because of Unhealthy ELB check?


def guess_service_name(lb_name):
    # NOTE: order, duplication matter
    for part in ('ec2-', 'elb-', 'prd-', 'elb-', 'prod-'):
        if lb_name.startswith(part):
            lb_name = lb_name[len(part):]

    # TODO: should -int is separated thing?
    if lb_name.endswith('-int'):
        lb_name = lb_name[:-4]

    # TODO: handle suffix number, like service-1 app-2... workaround when there are too much inbound rules
    if lb_name.endswith('-1'):
        lb_name = lb_name[:-2]

    return lb_name


def extract_elb_name_and_sgs_from_elb(lb):
    if isinstance(lb, str):
        # got pretend sg name, and get inbound of the SG
        all_security_groups = get_all_security_groups()
        sgs = [sg for sg in all_security_groups if sg['GroupName'].lower() == lb]
        inbound_sgs = []
        for sg in sgs:
            for inbound_rule in sg['IpPermissions']:
                inbound_sg_id = inbound_rule['UserIdGroupPairs'][0]['GroupId']
                inbound_sgs.append(inbound_sg_id)

        return lb, inbound_sgs
    else:
        return lb['LoadBalancerName'], lb['SecurityGroups']


def sgid_to_inbounds(sgid):
    # inbound rules -> security group ids -> security group name
    all_security_groups = get_all_security_groups()
    security_group = [sg for sg in all_security_groups if sg['GroupId'] == sgid]
    assert len(security_group) == 1, 'Should only 1 SG has given ID {}'.format(sgid)

    inbound_rules = security_group[0]['IpPermissions']

    internet_access = False
    groupsids = []
    for rule in inbound_rules:
        if rule['UserIdGroupPairs']:
            groupsids.append(rule['UserIdGroupPairs'])
        else:
            # UserIdGroupPairs empty means it is a CIDR rule - maybe check for internet incoming?
            if rule['FromPort'] in (80, 443):
                # TODO maybe check more
                internet_access = True

    sgs = [g['GroupId'] for L in groupsids for g in L]
    ret = {}
    try:
        if sgs:
            ret = {sg['GroupName']: sg['GroupId']
                   for sg in all_security_groups if sg['GroupId'] in sgs}
    except Exception as e:
        print(e)

    if internet_access:
        ret.update({'INTERNET': '1'})
    return ret


def find_security_groups_contain(service_name):
    all_security_groups = get_all_security_groups()
    service_name = service_name.lower()
    return [sg for sg in all_security_groups if service_name in sg['GroupName'].lower()]


def is_prod_sg(sg):
    return 'prd-' in sg['GroupName'] or 'prod-' in sg['GroupName']


def get_sg_name(sg):
    return sg['GroupName']


def get_main_security_groups(service_name):
    groups = [g for g in find_security_groups_contain(service_name) if is_prod_sg(g)]

    for sg in groups:
        inbounds = sgid_to_inbounds(sg['GroupId'])
        elb = {name: inbounds[name] for name in inbounds if 'elb-' in name}
        if elb:
            elb.update(
                {sg['GroupName']: sg['GroupId']}
            )
            return elb
    return {}


def elb_obj_to_all_inbounds(elb_obj):

    elb_name, elb_attached_sgs = extract_elb_name_and_sgs_from_elb(elb_obj)

    service = guess_service_name(elb_name)
    instance_sgs = get_main_security_groups(service).values()
    elb_attached_sgs.extend(instance_sgs)
    # TODO: matching all SGs with regex `name-\d` and uses them
    sgs = set(elb_attached_sgs)

    inbounds = {}
    for sg in sgs:
        inbounds.update(sgid_to_inbounds(sg))

    return inbounds


def get_services_access_elb(elb_obj):
    # TODO: use elb name instead of obj

    inbounds = elb_obj_to_all_inbounds(elb_obj)
    svcs = list(set([guess_service_name(inbound_name) for inbound_name in inbounds]))

    elb_name, _ = extract_elb_name_and_sgs_from_elb(elb_obj)
    print('{} has {} inbounds {}'.format(elb_name, len(inbounds), inbounds))

    def get_this_elb_service_name(elb_name):
        return guess_service_name(elb_name)

    this_elb_service_name = get_this_elb_service_name(elb_name)

    try:
        svcs.remove(this_elb_service_name)
    except ValueError:
        pass
    svcs.sort()
    print('{} has {} incoming connections from services {}'.format(this_elb_service_name, len(svcs), svcs))
    return svcs


def get_elb_object(elb_name, lbs=None):
    if lbs is None:
        lbs = get_all_load_balancers()

    return [elb_obj for elb_obj in lbs if elb_obj['LoadBalancerName']]


def get_elb_info(elb_name):
    resp = get_elb_object(elb_name)

    lb_objs = resp['LoadBalancerDescriptions']
    assert len(lb_objs) == 1
    return lb_objs[0]


def group_name_contain(servicename, g):
    return servicename in g['GroupName']


def get_cluster(groupname):
    return groupname.split('-')[0]


def get_cluster_from_sg(sg):
    return get_cluster(sg['GroupName'])


def get_env(security_groups, wanted_env):

    for env, sgs in itertools.groupby(sorted(security_groups, key=lambda x: x['GroupName']), get_cluster_from_sg):
        if env == wanted_env:
            return list(sgs)
    return []


def sg_names(sgs):
    return [sg['GroupName'] for sg in sgs]


def names(list_objs):

    for key in ('GroupName', 'RoleName', 'LoadBalancerName', 'AutoScalingGroupName', 'CacheClusterId', 'InstanceId'):
        try:
            return [obj[key] for obj in list_objs]
        except KeyError:
            continue

    raise Exception('Cannot get name of {}'.format(list_objs[0]))


def tags(tagged_object, tag_key='Tags'):
    return {tag['Key']: tag['Value']
            for tag in tagged_object.get(tag_key, {})}


def to_boto3_tags(tagdict):
    """
    Converts tag dict to list format that can feed to boto3 functions
    """
    return [{'Key': k, 'Value': v} for k, v in tagdict.items()
            if 'aws:' not in k]


def list_resource_tags(arn, client=None, backoff=30):
    if client is None:
        client = boto3.client('rds')

    while True:
        try:
            resp = client.list_tags_for_resource(
                ResourceName=arn
            )
            break
        except botocore.exceptions.ClientError as e:
            if 'RequestLimitExceeded' in str(e) or 'Throttling' in str(e):
                print("Sleep for %d seconds, throttled, error: %s" % (backoff, e))
                time.sleep(backoff)
            else:
                raise

    return tags(resp, 'TagList')


def instance_private_ip(instance):
    return instance.get('PrivateIpAddress')


def filter_by_service_name(botoresults, choice_func):
    return list(filter(choice_func, botoresults))


def group_by(things, func):
    for prefix, g in itertools.groupby(things, func):
        yield prefix, list(g)


# TODO maybe enum type for Role, Group... Name
def first_key_prefix(item, key='RoleName'):
    return item[key].split('-')[0]


def get_asg_of_service(service_name):
    service_asgs = filter_by_service_name(
        get_all_auto_scaling_groups(),
        lambda asg: 'prd-' in asg['AutoScalingGroupName'] and service_name == guess_service_name(asg['AutoScalingGroupName'])
    )
    assert len(service_asgs) == 1, "unhandled case {}".format(names(service_asgs))
    return service_asgs[0]


def get_asg_stats(asg):
    return {'MinSize': asg['MinSize'],
            'MaxSize': asg['MaxSize'],
            'DesiredCapacity': asg['DesiredCapacity'],
            }


def format_asg_stats(asg_stats):
    return "💻 {MinSize} <--- {DesiredCapacity} ---> {MaxSize}".format(**asg_stats)


# asg.describe_launch_configurations(LaunchConfigurationNames=[prd_asg['LaunchConfigurationName']])
getter = dict(
    asg=get_all_auto_scaling_groups,
    elasticache=get_all_cache_clusters,
    elb=get_all_load_balancers,
    sg=get_all_security_groups,
    ec2=get_all_ec2_instances,
    ebs=get_all_volumes,
    rds=get_all_rds_instances,
    roles=get_all_roles
)


def main():
    all_auto_scaling_groups = get_all_auto_scaling_groups()
    all_ec2_instances = get_all_ec2_instances()
    all_ec_clusters = get_all_cache_clusters()
    all_load_balancers = get_all_load_balancers()
    all_security_groups = get_all_security_groups()
    all_roles = get_all_roles()

    rep_groups = set()
    for i in all_ec_clusters:
        try:
            rep_groups.add(i['ReplicationGroupId'])
        except KeyError:
            pass
            # print('ERROR', i['CacheClusterId'])

    print(len(rep_groups))


if __name__ == "__main__":
    main()
