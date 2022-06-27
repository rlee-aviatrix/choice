# Choice

If VPC peering is used, security group rules can reference security groups in peered VPCs. If the VPC peering is deleted, these rules become stale. The following scripts create and associate new security groups which implement the same rules using private IPs instead of security group IDs so that VPC peerings can be deleted without impacting traffic.

- **duplicate-sg.py** - Creates a duplicate security group with security group references updated to use private IPs.
- **switch-sg.py** - Updates resources to use the newly duplicated security groups.

## Duplicate Security Groups (duplicate-sg.py)

**duplicate-sg.py** duplicates a security group with the following logic:

- Loops through all rules in the original security group
  - If a rule has a reference to its own security group ID, add a rule to the duplicate security group that references the duplicate security group ID.
  - If a rule has a reference to a security group that's in the same VPC as the original security group we're looping through, copy the rule as-is to the duplicate security group since it will not be affected when we delete the VPC peering.
  - If a rule has a reference to a security group that's in a different VPC, find all the private IPs associated with that security group and add corresonding rules to the duplicate security group for each IP. (This piece is only partially implemented.)
  - Otherwise that means there are no security group references so copy the rule as-is to the duplicate security group.
- All tags are copied from the original security group to the duplicate security group and an additional tag is added (currently set to whatever is specified for `aviatrix_tag_name` and `aviatrix_tag_value`).
- Duplicating security groups has no impact on traffic as the original security groups are still in use.

## Switch Security Groups (switch-sg.py)

**switch-sg.py** takes a list of "old" security groups and a list of "new" security groups as input. It looks through resources (currently network interfaces and security group rules) and updates any references to the "old" security groups with references to the "new" groups.

## Account Information (accounts.yml)

Since the scripts will need access to all AWS accounts to run properly, the access keys and secret access keys will need to be provided. Currently, the keys should be specified in `accounts.yml`. The account_id is also currently required because this reduces the number of API calls and simplifies the logic used in the script.

Example `accounts.yml`:

```
- account_id: 111111111111
  access_key_id: AAAAAAAAAAAAAAAAAAAA
  secret_access_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
- account_id: 222222222222
  access_key_id: BBBBBBBBBBBBBBBBBBBB
  secret_access_key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
```

## Questions

- What do we name the duplicate security group since security group names need to be unique?
- What tag(s) should we add to the duplicate security group if any? Maybe it makes sense to include the original security group ID? Should we add any tags to the original security groups to make it easier to find and delete later?
- Do we need to handle IPv6? This might work already but I haven't explicitly tested.
- When determining the private IP list, we currently get the `PrivateIpAddress` from `describe_network_interfaces`. There's also `PrivateIpAddresses` which is all private IPs assocated with the network interface. Should we be using the IPs from `PrivateIpAddresses` instead? Do we need to find private IPs from anything else besides network interfaces?
- In Switch Security Groups, we update the security groups associated with network interfaces and security group rules. Do we need to update security groups anywhere else?
- Is putting the access key and secret access key in `accounts.xml` ok?
- Additional discussion on the workflow. How should the user run the scripts? At the SG/VPC/account level?

## To Do

- Do testing across multiple AWS accounts
- Add logic to get private IPs from different accounts
- Add quota limit handling
- Add better print statements/output
- Add better exception/error handling
- Add a dry-run option to see what changes would be made without making them
