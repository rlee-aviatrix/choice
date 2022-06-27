import argparse

import boto3
import botocore
import yaml
import pprint

pp = pprint.PrettyPrinter()
aviatrix_tag_name = "CreatedBy"
aviatrix_tag_value = "Ron"


def switch_sg(old_sg_list, new_sg_list, client):
    response = client.describe_network_interfaces()
    nics = response["NetworkInterfaces"]
    for nic in nics:
        new_groups = []
        new_groups_modified = False
        for group in nic["Groups"]:
            if group["GroupId"] in old_sg_list:
                new_groups_modified = True
                new_groups.extend(new_sg_list)
            else:
                new_groups.append(group["GroupId"])
        # Use list/set to remove duplicates even though API seems to handle it
        if new_groups_modified:
            client.modify_network_interface_attribute(
                NetworkInterfaceId=nic["NetworkInterfaceId"],
                Groups=list(set(new_groups)),
            )
            print("Modifying NIC: ", nic["NetworkInterfaceId"])
            print("Security Groups: ", list(set(new_groups)), "\n")


def switch_sg_rule_ref(old_sg_list, new_sg_list, client):
    # response = client.describe_security_groups(
    #     Filters=[{"Name": "tag:" + aviatrix_tag_name, "Values": [aviatrix_tag_value]}]
    # )
    response = client.describe_security_groups()
    for sg in response["SecurityGroups"]:

        # Inbound rules
        for rule in sg["IpPermissions"]:
            ingress_rules_to_delete = []
            ingress_rules_to_add = []
            for pair in rule["UserIdGroupPairs"]:
                if pair["GroupId"] in old_sg_list:
                    ingress_rules_to_delete.append(pair["GroupId"])
                    ingress_rules_to_add.extend(new_sg_list)
            for each in list(set(ingress_rules_to_delete)):
                rule_to_delete = rule
                rule_to_delete["UserIdGroupPairs"] = [{"GroupId": each}]
                client.revoke_security_group_ingress(
                    GroupId=sg["GroupId"], IpPermissions=[rule_to_delete]
                )
            for each in list(set(ingress_rules_to_add)):
                rule_to_add = rule
                rule_to_add["UserIdGroupPairs"] = [{"GroupId": each}]
                try:
                    client.authorize_security_group_ingress(
                        GroupId=sg["GroupId"], IpPermissions=[rule_to_add]
                    )
                except botocore.exceptions.ClientError as error:
                    if error.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                        print(
                            "The rule", rule_to_add, "already exists in", sg["GroupId"]
                        )
                    else:
                        print("Something unexpected happened.")

        # Outbound rules
        for rule in sg["IpPermissionsEgress"]:
            egress_rules_to_delete = []
            egress_rules_to_add = []
            for pair in rule["UserIdGroupPairs"]:
                if pair["GroupId"] in old_sg_list:
                    egress_rules_to_delete.append(pair["GroupId"])
                    egress_rules_to_add.extend(new_sg_list)
            for each in list(set(egress_rules_to_delete)):
                rule_to_delete = rule
                rule_to_delete["UserIdGroupPairs"] = [{"GroupId": each}]
                client.revoke_security_group_egress(
                    GroupId=sg["GroupId"], IpPermissions=[rule_to_delete]
                )
            for each in list(set(egress_rules_to_add)):
                rule_to_add = rule
                rule_to_add["UserIdGroupPairs"] = [{"GroupId": each}]
                try:
                    client.authorize_security_group_egress(
                        GroupId=sg["GroupId"], IpPermissions=[rule_to_add]
                    )
                except botocore.exceptions.ClientError as error:
                    if error.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                        print(
                            "The rule", rule_to_add, "already exists in", sg["GroupId"]
                        )
                    else:
                        print("Something unexpected happened.")


def main():
    parser = argparse.ArgumentParser(description="Security Group Switcher")
    parser.add_argument("--old", nargs="+", required=True, help="Old security groups")
    parser.add_argument("--new", nargs="+", required=True, help="New security groups")
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
        sts = boto3.client(
            "sts",
            aws_access_key_id=account["access_key_id"],
            aws_secret_access_key=account["secret_access_key"],
            region_name="us-west-1",
        )
        if str(account["account_id"]) == sts.get_caller_identity()["Account"]:
            print("Account ID is Correct")
        else:
            print(
                "Account ID in yaml file differs from API response. Expected",
                account["account_id"],
                "but got",
                sts.get_caller_identity()["Account"],
            )
        switch_sg(args.old, args.new, client)
        switch_sg_rule_ref(args.old, args.new, client)


if __name__ == "__main__":
    main()
