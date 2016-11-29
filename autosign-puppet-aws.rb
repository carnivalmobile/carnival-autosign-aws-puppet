#!/opt/puppetlabs/puppet/bin/ruby
#
# Utility to validate Puppet CA/CSR requests against the instance data and tags
# via the AWS API to ensure legitimacy. Refer to README.md for more information.
#
#
#   Copyright (c) 2016 Sailthru, Inc., https://www.sailthru.com/
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

require 'puppet'
require 'puppet/ssl/oids'
require 'puppet/ssl/certificate_request'
require 'aws-sdk'
require 'logger'
require 'syslog/logger'

# When running under Puppet we can't get STDOUT/STDERR unless running Puppet in
# debug mode. So we should default to using syslog, unless an engineer running
# tests chooses not to.
if ENV['LOGSTDOUT'] == 'true'
  log = Logger.new(STDOUT)
else
  log = Syslog::Logger.new 'autosign'
end

# Puppet CA executes this script with the client cert name (usually the
# hostname) as an arguent and the full contents of the CSR as STDIN. Thanks to
# https://gist.github.com/jbouse/8763661 for the inspriration for using Puppet's
# own libraries to crunch the CSR and extract out any values that have been
# defined.

log.info "Processing supplied CSR (from STDIN)..."

clientcert = ARGV.pop
csr = Puppet::SSL::CertificateRequest.from_s(STDIN.read)

csr_extensions = Hash.new

Puppet::SSL::Oids::PUPPET_OIDS.each do |puppetoid|
  extendedvalue = csr.request_extensions.find { |a| a['oid'] == puppetoid[0] }

  unless extendedvalue.nil?
    csr_extensions[ puppetoid[1] ] = extendedvalue["value"]
  end
end

log.info "Extended values returned: " + csr_extensions.to_s

unless defined? csr_extensions['pp_instance_id']
  log.fatal "Failing CSR sign due to no `pp_instance_id` data supplied."
  exit 1
end

unless defined? csr_extensions['pp_region']
  log.fatal "Failing CSR sign due to no `pp_region` data supplied."
  exit 1
end


# Fetch the instance details from AWS.
log.info "Fetching instance infomation for #{csr_extensions['pp_instance_id']} from region #{csr_extensions['pp_region']}..."

Aws.config.update({
  region: csr_extensions['pp_region'],
})

client_ec2 = Aws::EC2::Client.new()
instance_details = client_ec2.describe_instances({
  instance_ids: [csr_extensions['pp_instance_id']],
  dry_run: false,
})

if instance_details.reservations.empty?
  log.fatal "Failing signing as instance does not exist."
  exit 1
end


# Ensure that we are trying to sign a running instance. Not much use signing
# anything that has already been terminated...
unless instance_details.reservations[0].instances[0].state.name == 'running'
  log.fatal "Failing signing as instance not running (current state: #{instance_details.reservations[0].instances[0].state.name})"
  exit 1
end


# Validate that the instance has a launch time less than 1800 seconds. This
# additional check is to ensure if an attacker has been able to manipulate EC2
# tags, they are restricted to a tight time window when new servers are
# provisioned.
if (Time.now.utc - instance_details.reservations[0].instances[0].launch_time) > 1800
  log.fatal "Failing signing as instance was launched more than 30mins ago, refusing to sign cert."
  exit 1
end


# Validate the instance name against the Name tag on the EC2 instance. We strip
# any FQDN extension and compare the hostname only.
instance_name_cert = clientcert.split('.')[0]

validated = false
instance_details.reservations[0].instances[0].tags.each do |tag|
  if tag["key"].downcase == 'name'
    instance_name_tag = tag["value"].downcase.split('.')[0]

    if instance_name_cert == instance_name_tag
      validated = true
    else
      log.fatal "Failing signing as certname #{instance_name_cert} does not match name tag with value of #{tag["value"]}."
      exit 1
    end
  end
end

if validated == false
  log.fatal "Failed signing as tag Name does not exist."
  exit 1
end


# Verify that this is the only instance with that name tag. Whilst Puppet won't
# allow cert name re-use, an attacker could create a new CSR with a different
# FQDN but same hostname and supply the instance ID of another existing
# instance. To protect against this, we have two measures - first the launch
# time restriction, but also this check to ensure the Name isn't being set twice
# anywhere in AWS EC2.

log.info "Verifying instance name tag is unique..."

instance_details_unique = client_ec2.describe_instances({
  filters:[{ name: "tag:Name", values: [instance_name_cert] }],
  dry_run: false,
})

if instance_details_unique.reservations.count > 1
  log.fatal "Failing signing as more than one server exists with the same name (multiple reservations). Enforce uniqueness."
  exit 1
end

if instance_details_unique.reservations[0].instances.count > 1
  log.fatal "Failing signing as more than one server exists with the same name (multiple instances in one reservation). Enforce uniqueness."
  exit 1
end


# Iterate through the Puppet extended values (other than instance_id and region)
 csr_extensions.each do |extension, value|
   unless extension == 'pp_instance_id' or extension == 'pp_region'
     # Drop the pp_ prefix from the extension value.
     extension = extension[3, extension.length].downcase
     value = value.downcase

     # Iterate through the tags. We lowercase the tag and values to avoid case
     # sensitivity headaches.
     validated = false
     instance_details.reservations[0].instances[0].tags.each do |tag|
       if tag["key"].downcase == extension
         log.info "Validating tag #{extension} (expected value: #{value})"
         if tag["value"].downcase == value
           validated = true
         else
           log.fatal "Failing signing as tag #{extension} value is #{tag["value"]} rather than expected #{value}"
           exit 1
         end
       end
     end

     if validated == false
       log.fatal "Failed signing as tag #{extension} does not exist."
       exit 1
     end
   end
 end


# We passed the gauntlet! Approve certificate for signing.
log.info "All validations passed, certificate #{clientcert} approved."
exit 0
