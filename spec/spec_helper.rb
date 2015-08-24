# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
# running the grok code outside a logstash package means
# LOGSTASH_HOME will not be defined, so let's set it here
# before requiring the grok filter
unless LogStash::Environment.const_defined?(:LOGSTASH_HOME)
  LogStash::Environment::LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
end
require 'logstash/filters/syslog_pri'
require 'logstash/filters/grok'

module SyslogHelpers

  def parse(event)
    config = { "match" => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGBASE2}"} }
    grok = LogStash::Filters::Grok.new(config)
    grok.register
    grok.filter(event)
    return event
  end

end

RSpec.configure do |c|
  c.include SyslogHelpers
end
