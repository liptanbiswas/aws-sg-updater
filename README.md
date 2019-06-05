# AWS Security Group Updater

**How to use.**

./aws-sg-updater -t liptan -i sg-63stf4gst637 -i sg-74744nnnn4n4n

Options.
 - `-t` Tag name for identifying security group rule. It will be put in description of security group rule.
 - `-i` AWS Security Group IDs.


The program reads AWS credentials from `~/.aws/credentials`.

 - If security group rule having description as passed tag is not found, it will add a new security group with your WAN Ip address and all ports open.
 - If security group rule having description as passed tag is found, but WAN IP and IP in AWS security group is equal, it will remove the old security group rule and add new one.
 - If security group rule having description as passed tag is found, and WAN IP and IP in AWS security group is equal, it will do nothing.
