# Carnival AWS-Puppet Autosigner

## Overview

This is a Puppet policy-based autosigner which allows Puppet signing requests to
to validated against the instance data and tags provided via the AWS API to
ensure legitimacy.


## Background

Puppet is a great way of managing servers and to start treating servers like
cattle rather than pets. However this new cattle-first frontier brings with it
some issues - how do we ensure that when a server is provisioned automatically
it only receives the configuration that's truely appropiate?

In a traditional environment it might be feasible to approve a server
certificate request manually, one at a time, but this doesn't scale or work for
an automated cloud environment.

An exploited web server inside your network could easily claim to be a
"production database server" in an attempt to steal configuration or credentials
to more appealing targets.

So we can't simply permit any system on the network to request configuration.
One common attempt to resolve this is the use of pre-shared certs/keys to
validate the identity of a server at launch. The problem with this approach is
that it's implementers rarely create a pre-shared cert/key per unique role, so
any attacker with access to the general site-wide pre-shared cert/key can
provision any other server. And given that these pre-shared certs/keys are
typically stored or linked to from user data, capturing them is a trivial
exercise.

This policy-based autosigner solves this problem by instead evaluating every
signing request the Puppet master/CA receives, against the data provided by the
AWS APIs for each instance.


## Verifying Legitimacy

The autosigner validates the legitimacy of a request by checking:

* The instance ID exists, AND

* We have not signed this instance ID before (tracked on Puppet master, assumes
  shared disk), AND

* The instance `Name` tag matches the requested cert name, AND

* Administrator-selected trusted facts baked into the cert match tags on the
  instance. Eg you may wish to match `environment` or `role` or some other
  attribute used to categorize the servers, AND

* The instance has a launch time less than 1800 seconds. This additional check
  is to ensure if an attacker has been able to manipulate EC2 tags, they are
  restricted to a tight time window when new servers are provisioned.

To ensure the integrity of this process, your instances should not have
permission to tag instances, including themselves. Any instance tagging is best
done out-of-band by trusted applications, a task which has gotten much easier
thanks to AWS Lambda and Cloudwatch events.

TODO: link to example OOB Lambda-based namer?



# Configuration

## On Puppet Nodes (client-side)

In order to help the autosigner perform validations, any attributes that you
need available as a [trusted fact](https://docs.puppet.com/puppet/4.8/reference/lang_facts_and_builtin_vars.html#trusted-facts)
needs to be included inside the CSR attributes for each node.

This can be accomplished with the [ssl attributes extension](https://docs.puppet.com/puppet/4.8/reference/ssl_attributes_extensions.html)
feature of Puppet which allows us to pass through values as part of the signing
process. We then validate those values with the autosigner to ensure the
integrity of the data.

To make this work, you will need to setup a `csr_attributes.yaml` file on each
Puppet client *before* they run Puppet for the first time to populate their CSR
with additional attributes.

Puppet provides a large number of pre-defined keys you can use for these values
and offer complete flexibility as to what you put inside them. The following is
a suggested example:

    cat > /etc/puppetlabs/puppet/csr_attributes.yaml << EOF
    ---
    extension_requests:
        # These will vary to meet the requirements of your specific site. Refer to
        # https://docs.puppet.com/puppet/4.8/reference/ssl_attributes_extensions.html#puppet-specific-registered-ids
        # for a list of all pre-defined IDs you can take advantage of

        # Required for autosigner:
        pp_instance_id: $(facter -p ec2_metadata.instance-id)
        pp_region: $(facter -p ec2_metadata.placement.availability-zone | sed 's/[a-z]$//')

        # Adjust to meet your requirements:
        pp_environment: $(facter -p environment)
        pp_role: $(facter -p role)
    EOF

After signing, these values will be available inside Puppet in the form of the
`$trusted['extensions']['NAME']`, eg the above would provide:

    $trusted['extensions']['pp_instance_id']
    $trusted['extensions']['pp_region']
    $trusted['extensions']['pp_role']
    $trusted['extensions']['pp_environment']

These can also be used inside Hiera, for example:

    :hierarchy:
      - "nodes/%{::trusted.certname}"
      - "roles/%{::trusted.extensions.pp_role}"
      - "environments/%{::trusted.extensions.pp_environment}"
      - users
      - common



## On Puppet Master (server-side)

The autosigner application itself does not require any specific configuration.
However the server itself must have a proper IAM role and Puppet needs to be
configured to use the autosigner.

The following IAM role permits the Puppet master to read EC2 instance details of
all instances in the account (however not manipulate them).

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "ec2:DescribeInstances"
          ],
          "Resource": "*",
          "Effect": "Allow"
        }
      ]
    }

Note this IAM policy can be locked down pre-account & per-region, however the
`ec2:DescribeInstances` action does not support conditionals such as VPC or tag
specific restrictions.

The Puppet master configuration is simple - we just need to set autosign to
point to the executable on disk.

    [master]
      autosign = /usr/local/bin/autosign-puppet-aws


# Deployment

Note that we use the Puppet labs bundled version of Ruby as it includes the gem
for Puppet and a consistent version of Ruby across our server fleet. If your
version of Puppet is installed elsewhere, you may need to amend.

    /opt/puppetlabs/puppet/bin/gem install aws-sdk
    cp autosign-puppet-aws.rb /usr/local/bin/autosign-puppet-aws



# Troubleshooting

## Validating CSR Generation

When the first Puppet run occurs, there should be a log entry regarding the
csr_attributes file:

    Info: csr_attributes file loading from /etc/puppetlabs/puppet/csr_attributes.yaml

You can check if the CSR includes the attributes with:

    openssl req -noout -text -in \
    /etc/puppetlabs/puppet/ssl/certificate_requests/*.pem

## Something went wrong whilst signing

If the signing was refused, check the syslog on the Puppet master(s). Logs are
tagged `autosign`.

Note that if the code throws an exception, it isn't captured in syslog. If you
believe there is an uncaught exception, see the 'Testing script directly'
section below for how to run directly to validate.

## Something went wrong and I can't get an instance to sign

If the signing process fails part way through, it can upset either the Puppet
master or the client and prevent future signings working for the client. If this
happens, remove `/etc/puppetlabs/puppet/ssl` directory and contents on the
client and run `puppet cert clean CERTNAME` on the master.


## Checking Logs

The autosigner output is logged directly to syslog. This will include all the
details around any failures


## Testing script directly

You can test the script directly with the following command:

    export LOGSTDOUT=true
    export STATETRACKING=/tmp
    cat testcsr.pem | ruby autosign-puppet-aws.rb staging-teststack-a4a8ab5c


# Further Reading

For more information about the Puppet SSL autosigning process, refer to the
official documentation at https://docs.puppet.com/puppet/latest/reference/ssl_autosign.html


# Contributions

All contributions are welcome via Pull Requests including documentation fixes.


# License

    Copyright (c) 2016 Sailthru, Inc., https://www.sailthru.com/

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
