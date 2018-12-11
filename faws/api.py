# Define api for things

from . import core


def ls(resource_name='ec2'):
    '''return all ec2 instances name'''
    assert resource_name in core.RESOURCES, 'Unsupported resource {}. Only support {}'.format(resource_name, ', '.join(core.RESOURCES))
    return core.names(ls_obj(resource_name))


def ls_obj(resource_name='ec2'):
    '''
    Returns all ec2 instance info (dict)
    '''
    return core.getter[resource_name]()


if __name__ == "__main__":
    for resource in core.RESOURCES:
        print('We have {} {}'.format(len(ls(resource)), resource))
