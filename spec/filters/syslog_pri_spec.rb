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

    let(:properties) { { "syslog_pri" => 1 } }
    let(:event)      { LogStash::Event.new(properties) }

    before(:each) do
      subject.register
    end

    it "default syslog_facility is user-level" do
      subject.filter(event)
      expect(event.get("syslog_facility")).to eq("user-level")
    end

    it "default syslog severity is notice" do
      subject.filter(event)
      expect(event.get("syslog_severity")).to eq("notice")
    end

    it "default severity to be 5, out of priority default 13" do
      subject.filter(event)
      expect(event.get("syslog_severity_code")).to eq(5)
    end

  end

  describe "filtering" do

    let(:properties) { { "syslog_pri" => syslog_pri } }
    let(:event)      { LogStash::Event.new(properties) }

    before(:each) do
      subject.register
    end

    context "when critical messages arrive" do
      let(:syslog_pri) { 34 }

      it "syslog severity is critical" do
        subject.filter(event)
        expect(event.get("syslog_severity")).to eq("critical")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event.get("syslog_facility")).to eq("security/authorization")
      end

    end

    context "when notice local messages arrive" do
      let(:syslog_pri) { 165 }

      it "syslog severity is notice" do
        subject.filter(event)
        expect(event.get("syslog_severity")).to eq("notice")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event.get("syslog_facility")).to eq("local4")
      end
    end

    context "when a debug messages arrive" do
      let(:syslog_pri) { 191 }

      it "syslog severity is notice" do
        subject.filter(event)
        expect(event.get("syslog_severity")).to eq("debug")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event.get("syslog_facility")).to eq("local7")
      end
    end

    context "when an alert messages arrive" do
      let(:syslog_pri) { 137 }

      it "syslog severity is notice" do
        subject.filter(event)
        expect(event.get("syslog_severity")).to eq("alert")
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        expect(event.get("syslog_facility")).to eq("local1")
      end
    end

  end

end
