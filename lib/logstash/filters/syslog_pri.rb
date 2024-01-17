# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# Filter plugin for logstash to parse the `PRI` field from the front
# of a Syslog (RFC3164) message.  If no priority is set, it will
# default to 13 (per RFC).
class LogStash::Filters::Syslog_pri < LogStash::Filters::Base

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)

  config_name "syslog_pri"

  # Add human-readable names after parsing severity and facility from PRI
  config :use_labels, :validate => :boolean, :default => true

  # Name of field which passes in the extracted PRI part of the syslog message
  # default: 'syslog_pri' or '[log][syslog][priority]' with ECS
  config :syslog_pri_field_name, :validate => :string

  # Labels for facility levels. This comes from RFC3164.
  config :facility_labels, :validate => :array, :default => [
    "kernel",
    "user-level",
    "mail",
    "daemon",
    "security/authorization",
    "syslogd",
    "line printer",
    "network news",
    "uucp",
    "clock",
    "security/authorization",
    "ftp",
    "ntp",
    "log audit",
    "log alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
  ]

  # Labels for severity levels. This comes from RFC3164.
  config :severity_labels, :validate => :array, :default => [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
  ]

  def initialize(*params)
    super

    @facility_code_key = ecs_select[disabled:'syslog_facility_code', v1:'[log][syslog][facility][code]']
    @severity_code_key = ecs_select[disabled:'syslog_severity_code', v1:'[log][syslog][severity][code]']

    @facility_label_key = ecs_select[disabled:'syslog_facility', v1:'[log][syslog][facility][name]']
    @severity_label_key = ecs_select[disabled:'syslog_severity', v1:'[log][syslog][severity][name]']

    # config parameter default:
    @syslog_pri_field_name ||= ecs_select[disabled:'syslog_pri', v1:'[log][syslog][priority]']
  end

  def register
    # Nothing
  end # def register

  def filter(event)
    parse_pri(event)
    filter_matched(event)
  end # def filter

  private

  SYSLOGPRIPARSEFAILURE_TAG = "_syslogpriparsefailure"

  def parse_pri(event)
    # Per RFC3164, priority = (facility * 8) + severity
    # = (facility << 3) & (severity)
    priority = event.get(@syslog_pri_field_name)
    if priority
      if priority.is_a?(Array)
        priority = priority.first.to_i
      else
        priority = priority.to_i
      end
    else
      priority = 13  # default
    end

    severity_code = priority & 7 # 7 is 111 (3 bits)
    facility_code = priority >> 3
    event.set(@severity_code_key, severity_code)
    event.set(@facility_code_key, facility_code)

    # Add human-readable names after parsing severity and facility from PRI
    return unless @use_labels

    # from Syslog PRI RFC 4.1.1 PRI Part, facility_code the maximum possible value is 124, however it defines just 23 values
    if facility_code > (@facility_labels.size - 1)
      # if the facility_code overflow the labels array
      event.tag(SYSLOGPRIPARSEFAILURE_TAG)
      logger.debug("Invalid facility code for event", :facility => facility_code)
      return
    end

    facility_label = @facility_labels[facility_code]
    event.set(@facility_label_key, facility_label) if facility_label

    # severity code is in range [0..7] by definition, no need to check any bound
    severity_label = @severity_labels[severity_code]
    event.set(@severity_label_key, severity_label) if severity_label
  end # def parse_pri
end # class LogStash::Filters::SyslogPRI
