# encoding: utf-8
require_relative "../spec_helper"
require "logstash/plugin"
require "logstash/event"

describe LogStash::Filters::Syslog_pri do

  let(:options)    { {} }
  subject          { LogStash::Filters::Syslog_pri.new(options) }
  let(:event_data) { { :name => "foo" } }
  let(:event)      { LogStash::Event.new.tap { |event| event_data.each { |k, v| event.set(k, v) } } }

  it "should register without errors" do
    plugin = LogStash::Plugin.lookup("filter", "syslog_pri").new( "facility_labels" => ["kernel"] )
    expect { plugin.register }.to_not raise_error
  end

  context 'defaults', :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

      let(:ecs_compatibility?) { ecs_select.active_mode != :disabled }

      let(:options)    { { "syslog_pri_field_name" => "my_syslog_pri" } }
      let(:event_data) { { (ecs_compatibility? ? "[log][syslog][priority]" : "syslog_pri") => 1 } }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)

        subject.register
      end

      it "default syslog_facility is user-level" do
        subject.filter(event)
        if ecs_compatibility?
          expect(event.get("[log][syslog][facility][name]")).to eq("user-level")
        else
          expect(event.get("syslog_facility")).to eq("user-level")
        end
      end

      it "default syslog severity is notice" do
        subject.filter(event)
        if ecs_compatibility?
          expect(event.get("[log][syslog][severity][name]")).to eq("notice")
        else
          expect(event.get("syslog_severity")).to eq("notice")
        end
      end

      it "default severity to be 5, out of priority default 13" do
        subject.filter(event)
        if ecs_compatibility?
          expect(event.get("[log][syslog][severity][code]")).to eq(5)
        else
          expect(event.get("syslog_severity_code")).to eq(5)
        end
      end

      it "defaults to facility 1" do
        subject.filter(event)
        if ecs_compatibility?
          expect(event.get("[log][syslog][facility][code]")).to eq(1)
        else
          expect(event.get("syslog_facility_code")).to eq(1)
        end
      end

    end
  end

  context 'filtering', :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled, :v1) do |ecs_select|

      let(:ecs_compatibility?) { ecs_select.active_mode != :disabled }

      let(:event_data) { { (ecs_compatibility? ? "[log][syslog][priority]" : "syslog_pri") => syslog_pri } }

      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)

        subject.register
      end

      context "when critical messages arrive" do
        let(:syslog_pri) { 34 }

        it "syslog severity is critical" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][severity][name]")).to eq("critical")
          else
            expect(event.get("syslog_severity")).to eq("critical")
          end
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][facility][name]")).to eq("security/authorization")
          else
            expect(event.get("syslog_facility")).to eq("security/authorization")
          end
        end

      end

      context "when notice local messages arrive" do
        let(:syslog_pri) { 165 }

        it "syslog severity is notice" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][severity][name]")).to eq("notice")
          else
            expect(event.get("syslog_severity")).to eq("notice")
          end
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][facility][name]")).to eq("local4")
          else
            expect(event.get("syslog_facility")).to eq("local4")
          end
        end
      end

      context "when a debug messages arrive" do
        let(:syslog_pri) { 191 }

        it "syslog severity is notice" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][severity][name]")).to eq("debug")
          else
            expect(event.get("syslog_severity")).to eq("debug")
          end
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][facility][name]")).to eq("local7")
          else
            expect(event.get("syslog_facility")).to eq("local7")
          end
        end
      end

      context "when an alert messages arrive" do
        let(:syslog_pri) { '137' }

        it "syslog severity is notice" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][severity][name]")).to eq("alert")
          else
            expect(event.get("syslog_severity")).to eq("alert")
          end
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          if ecs_compatibility?
            expect(event.get("[log][syslog][facility][name]")).to eq("local1")
            expect(event.get("[log][syslog][facility][code]")).to eq(17)
          else
            expect(event.get("syslog_facility")).to eq("local1")
            expect(event.get("syslog_facility_code")).to eq(17)
          end
        end
      end

    end
  end
end
