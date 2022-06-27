import argparse
import botocore
import boto3
import yaml
import pprint

pp = pprint.PrettyPrinter()
aviatrix_tag_name = "CreatedBy"
aviatrix_tag_value = "Ron"


# Returns a list of private IPs assocatied with a security group
def get_private_ips(sg_id, account_id):
    private_ip_list = []
    with open("accounts.yml", "r") as f:
        accounts = yaml.load(f, Loader=yaml.FullLoader)
    for account in accounts:
        print(type(account["account_id"]))
        print(type(account_id))
        if str(account["account_id"]) == account_id:
            print("account matches")
            client = boto3.client(
                "ec2",
                aws_access_key_id=account["access_key_id"],
                aws_secret_access_key=account["secret_access_key"],
                region_name="us-west-1",
            )
            response = client.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [sg_id]}]
            )
            for nic in response["NetworkInterfaces"]:
                private_ip_list.append(nic["PrivateIpAddress"])
                print(nic["PrivateIpAddress"])
    return private_ip_list


# Returns true if there are any rules that reference security groups in a different VPC
def should_be_duplicated(security_group_id, client):
    response = client.describe_security_groups(GroupIds=[security_group_id])
    should_be_duplicated = False
    pp.pprint(response)
    for sg in response["SecurityGroups"]:
        for rule in sg["IpPermissions"]:
            for pair in rule["UserIdGroupPairs"]:
                if sg["VpcId"] != get_sg_vpcid(pair["GroupId"], pair["UserId"]):
                    should_be_duplicated = True
        for rule in sg["IpPermissionsEgress"]:
            for pair in rule["UserIdGroupPairs"]:
                if sg["VpcId"] != get_sg_vpcid(pair["GroupId"], pair["UserId"]):
                    should_be_duplicated = True
    return should_be_duplicated


# Returns the VPC ID of the VPC that a security group is in
def get_sg_vpcid(sg_id, userid):
    with open("accounts.yml", "r") as f:
        accounts = yaml.load(f, Loader=yaml.FullLoader)

    for account in accounts:
        if str(account["account_id"]) == userid:
            client = boto3.client(
                "ec2",
                aws_access_key_id=account["access_key_id"],
                aws_secret_access_key=account["secret_access_key"],
                region_name="us-west-1",
            )
            response = client.describe_security_groups(GroupIds=[sg_id])
            return response["SecurityGroups"][0]["VpcId"]


def duplicate_sg(original_sg_id, new_groupname, client):
    original_sg = client.describe_security_groups(GroupIds=[original_sg_id])
    aviatrix_tags = {"Key": aviatrix_tag_name, "Value": aviatrix_tag_value}
    new_tags = original_sg["SecurityGroups"][0]["Tags"]
    new_tags.append(aviatrix_tags)
    try:
        new_sg = client.create_security_group(
            Description=original_sg["SecurityGroups"][0]["Description"],
            GroupName=new_groupname,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": new_tags}],
        )
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "InvalidGroup.Duplicate":
            print("Duplicate Security Group", new_groupname, "already exists.")
            return

    # Inbound Rules

    new_ippermissions_ingress = []

    for ippermission in original_sg["SecurityGroups"][0]["IpPermissions"]:
        original_sg_vpc = client.describe_security_groups(GroupIds=[original_sg_id])[
            "SecurityGroups"
        ][0]["VpcId"]

        # If there are no useridgrouppairs, that means there are no rerefences, just append the rule
        if len(ippermission["UserIdGroupPairs"]) == 0:
            new_ippermissions_ingress.append(ippermission)
        for useridgrouppair in ippermission["UserIdGroupPairs"]:
            referenced_sg_vpc = client.describe_security_groups(
                GroupIds=[useridgrouppair["GroupId"]]
            )["SecurityGroups"][0]["VpcId"]

            # If the security group referenced is the ID of the security group itself
            # the duplicate security group should reference its own ID instead of the ID of the original
            if useridgrouppair["GroupId"] == original_sg_id:
                useridgrouppair["GroupId"] = new_sg["GroupId"]
                ippermission["UserGroupPairs"] = [ippermission]
                new_ippermissions_ingress.append(ippermission)

            # Check if the referenced SG is in the same VPC as the origianl
            # If they are, append the rule as is
            elif referenced_sg_vpc == original_sg_vpc:
                new_ippermissions_ingress.append(ippermission)

            # Add else case where we need to find private IPs related to the SG

            else:
                print("add get private ips later")

    if len(new_ippermissions_ingress) > 0:
        client.authorize_security_group_ingress(
            GroupId=new_sg["GroupId"], IpPermissions=new_ippermissions_ingress
        )

    # Outbound Rules

    # Remove the default allow all egress rule in the duplicate security group so we can duplicate all rules in the original security group
    client.revoke_security_group_egress(
        GroupId=new_sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            }
        ],
    )

    new_ippermissions_egress = []

    for ippermission in original_sg["SecurityGroups"][0]["IpPermissionsEgress"]:
        original_sg_vpc = client.describe_security_groups(GroupIds=[original_sg_id])[
            "SecurityGroups"
        ][0]["VpcId"]

        # If there are no useridgrouppairs, that means there are no rerefences, just append the rule
        if len(ippermission["UserIdGroupPairs"]) == 0:
            new_ippermissions_egress.append(ippermission)
        for useridgrouppair in ippermission["UserIdGroupPairs"]:
            referenced_sg_vpc = client.describe_security_groups(
                GroupIds=[useridgrouppair["GroupId"]]
            )["SecurityGroups"][0]["VpcId"]

            # If the security group referenced is the ID of the security group itself
            # the duplicate security group should reference its own ID instead of the ID of the original
            if useridgrouppair["GroupId"] == original_sg_id:
                useridgrouppair["GroupId"] = new_sg["GroupId"]
                ippermission["UserGroupPairs"] = [ippermission]
                new_ippermissions_egress.append(ippermission)

            # Check if the referenced SG is in the same VPC as the origianl
            # If they are, append the rule as is
            elif referenced_sg_vpc == original_sg_vpc:
                new_ippermissions_egress.append(ippermission)

            # Add else case where we need to find private IPs related to the SG
            else:
                print("add get private ips later")

    if len(new_ippermissions_egress) > 0:
        client.authorize_security_group_egress(
            GroupId=new_sg["GroupId"], IpPermissions=new_ippermissions_egress
        )


def main():
    parser = argparse.ArgumentParser(description="Security Group Duplicator")
    parser.add_argument("--source", nargs="+", help="Source security group")
    # parser.add_argument("--destination", nargs="+", help="Destination security groups")
    args = parser.parse_args()

    with open("accounts.yml", "r") as f:
        accounts = yaml.load(f, Loader=yaml.FullLoader)

    for account in accounts:
        client = boto3.client(
            "ec2",
            aws_access_key_id=account["access_key_id"],
            aws_secret_access_key=account["secret_access_key"],
            region_name="us-west-1",
        )
        duplicate_sg("sg-075f9c070daee92df", "SG-Test1-dupe", client)


if __name__ == "__main__":
    main()
