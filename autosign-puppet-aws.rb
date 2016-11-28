#!/usr/bin/env ruby
#
# Utility to validate Puppet CA/CSR requests against the instance data and tags
# via the AWS API to ensure legitimacy. Refer to README.md for more information.
#

require 'puppet'
require 'puppet/ssl/oids'
require 'puppet/ssl/certificate_request'
require 'aws-sdk'


# Puppet CA executes this script with the client cert name (usually the
# hostname) as an arguent and the full contents of the CSR as STDIN. Thanks to
# https://gist.github.com/jbouse/8763661 for the inspriration for using Puppet's
# own libraries to crunch the CSR and extract out any values that have been
# defined.

puts "[autosign] Processing supplied CSR..."

clientcert = ARGV.pop
csr = Puppet::SSL::CertificateRequest.from_s(STDIN.read)

csr_extensions = Hash.new

Puppet::SSL::Oids::PUPPET_OIDS.each do |puppetoid|
  extendedvalue = csr.request_extensions.find { |a| a['oid'] == puppetoid[0] }

  unless extendedvalue.nil?
    csr_extensions[ puppetoid[1] ] = extendedvalue["value"]
  end
end

puts "[autosign] Extended values returned: " + csr_extensions.to_s

unless defined? csr_extensions['pp_instance_id']
  puts "[autosign] Failing CSR sign due to no `pp_instance_id` data supplied."
  exit 1
end

unless defined? csr_extensions['pp_region']
  puts "[autosign] Failing CSR sign due to no `pp_region` data supplied."
  exit 1
end


# Fetch the instance details from AWS.
puts "[autosign] Fetching instance infomation for #{csr_extensions['pp_instance_id']} from region #{csr_extensions['pp_region']}..."

Aws.config.update({
  region: csr_extensions['pp_region'],
})

client_ec2 = Aws::EC2::Client.new()
instance_details = client_ec2.describe_instances({
  instance_ids: [csr_extensions['pp_instance_id']],
  dry_run: false,
})

# Validate attributes
unless instance_details.reservations[0].instances[0].state.name == 'running'
  puts "[autosign] Failing signing as instance not running (current state: #{instance_details.reservations[0].instances[0].state.name})"
  exit 1
end

# TODO: Convert and validate launch time.
puts instance_details.reservations[0].instances[0].launch_time

# TODO: Validate tags against puppet params
puts instance_details.reservations[0].instances[0].tags
