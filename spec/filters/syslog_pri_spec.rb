# encoding: utf-8
require_relative "../spec_helper"
require "logstash/plugin"
require "logstash/event"

describe LogStash::Filters::Syslog_pri do

  subject          { LogStash::Filters::Syslog_pri.new( "syslog_pri_field_name" => "syslog_pri" ) }
  let(:properties) { {:name => "foo" } }
  let(:event)      { LogStash::Event.new(properties) }

  it "should register without errors" do
    plugin = LogStash::Plugin.lookup("filter", "syslog_pri").new( "facility_labels" => ["kernel"] )
    expect { plugin.register }.to_not raise_error
  end

  describe "filtering" do

    let(:msg) { "<1>Sep 20 02:58:12 porridge3 puppet-master[27025]: Compiled catalog for bigbopper.adm.intranet in environment production in 1.31 seconds\n" }

    let(:properties) {{ "message" => msg }}

    before(:each) do
      subject.register
    end

    it "should syslog_facility be extracted" do
      subject.filter(event)
      expect(event["syslog_facility"]).to eq("user-level")
    end

    it "should syslog severity be extracted" do
      subject.filter(event)
      expect(event["syslog_severity"]).to eq("notice")
    end

    it "should syslog severity code be extracted" do
      subject.filter(event)
      expect(event["syslog_severity_code"]).to eq(5)
    end

  end

  describe "defaults" do

    let(:msg) { "<2> Sep 20 02:58:12 porridge3 puppet-master[27025]: Compiled catalog for bigbopper.adm.intranet in environment production in 1.31 seconds\n" }

    let(:properties) {{ "message" => msg }}

    before(:each) do
      subject.register
    end

    it "defaults priority to 13" do
      subject.filter(event)
      expect(event["syslog_facility_code"]).to eq(1)
    end

  end

end
