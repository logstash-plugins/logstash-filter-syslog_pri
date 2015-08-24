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

  describe "defaults" do

    subject          { LogStash::Filters::Syslog_pri.new( "syslog_pri_field_name" => "my_syslog_pri" ) }

    let(:msg)        { "<1>Sep 20 02:58:12 porridge3 puppet-master[27025]: Compiled catalog for bigbopper.adm.intranet in environment production in 1.31 seconds\n" }
    let(:properties) {{ "message" => msg }}
    let(:event)      { parse(LogStash::Event.new(properties)) }

    before(:each) do
      subject.register
    end

    it "default syslog_facility is user-level" do
      subject.filter(event)
      expect(event["syslog_facility"]).to eq("user-level")
    end

    it "default syslog severity is notice" do
      subject.filter(event)
      expect(event["syslog_severity"]).to eq("notice")
    end

    it "default severity to be 5, out of priority default 13" do
      subject.filter(event)
      expect(event["syslog_severity_code"]).to eq(5)
    end

  end

  describe "filtering" do

    let(:properties) {{ "message" => msg }}
    let(:event)      { parse(LogStash::Event.new(properties)) }

    before(:each) do
      subject.register
    end

    context "when critical messages arrive" do
      let(:msg)        { "<34>Sep 20 02:58:12 porridge3 puppet-master[27025]: Compiled catalog for bigbopper.adm.intranet in environment production in 1.31 seconds\n" }

      it "syslog severity is critical" do
        subject.filter(event)
        expect(event["syslog_severity"]).to eq("critical")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event["syslog_facility"]).to eq("security/authorization")
      end

    end

    context "when notice local messages arrive" do
      let(:msg)        { "<165>Sep 20 02:58:12 porridge3 puppet-master[27025]: Compiled catalog for bigbopper.adm.intranet in environment production in 1.31 seconds\n" }

      it "syslog severity is notice" do
        subject.filter(event)
        expect(event["syslog_severity"]).to eq("notice")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event["syslog_facility"]).to eq("local4")
      end
    end

    context "when a debug messages arrive" do
      let(:msg)        { "<191>Sep 20 02:58:12 porridge3 puppet-master[27025]: Compiled catalog for bigbopper.adm.intranet in environment production in 1.31 seconds\n" }

      it "syslog severity is notice" do
        subject.filter(event)
        expect(event["syslog_severity"]).to eq("debug")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event["syslog_facility"]).to eq("local7")
      end
    end

    context "when an alert messages arrive" do
      let(:msg)        { "<137>Sep 20 02:58:12 porridge3 puppet-master[27025]: Compiled catalog for bigbopper.adm.intranet in environment production in 1.31 seconds\n" }

      it "syslog severity is notice" do
        subject.filter(event)
        expect(event["syslog_severity"]).to eq("alert")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event["syslog_facility"]).to eq("local1")
      end
    end

  end

end
