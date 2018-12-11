# -*- coding: utf-8 -*-

"""Console script for faws."""
import sys
import click


@click.command()
@click.argument('name')
def main(name):
    """Console script for faws."""
    import faws
    ec2 = faws.ls_obj('ec2')
    for i in ec2:
        instance_name_tag = faws.core.tags(i).get('Name', '').lower()
        if name in instance_name_tag:
            print('{:<30}{:<16}{:<18}'.format(instance_name_tag, faws.core.instance_private_ip(i), i['InstanceId']))
    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
