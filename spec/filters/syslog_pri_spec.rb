# encoding: utf-8
require_relative "../spec_helper"
require "logstash/plugin"
require "logstash/event"

describe LogStash::Filters::Syslog_pri do

  let(:options)    { {} }
  subject          { LogStash::Filters::Syslog_pri.new(options) }
  let(:event_data) { { :name => "foo" } }
  let(:event)      { LogStash::Event.new.tap { |event| event_data.each { |k, v| event.set(k, v) } } }
  let(:syslog_facility_code_field) { ecs_compatibility? ? "[log][syslog][facility][code]" : "syslog_facility_code" }
  let(:syslog_facility_name_field) { ecs_compatibility? ? "[log][syslog][facility][name]" : "syslog_facility" }
  let(:syslog_severity_code_field) { ecs_compatibility? ? "[log][syslog][severity][code]" : "syslog_severity_code" }
  let(:syslog_severity_name_field) { ecs_compatibility? ? "[log][syslog][severity][name]" : "syslog_severity" }

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
        expect(event.get(syslog_facility_name_field)).to eq("user-level")
      end

      it "default syslog severity is notice" do
        subject.filter(event)
        expect(event.get(syslog_severity_name_field)).to eq("notice")
      end

      it "default severity to be 5, out of priority default 13" do
        subject.filter(event)
        expect(event.get(syslog_severity_code_field)).to eq(5)
      end

      it "defaults to facility 1" do
        subject.filter(event)
        expect(event.get(syslog_facility_code_field)).to eq(1)
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
          expect(event.get(syslog_severity_name_field)).to eq("critical")
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          expect(event.get(syslog_facility_name_field)).to eq("security/authorization")
        end

      end

      context "when notice local messages arrive" do
        let(:syslog_pri) { 165 }

        it "syslog severity is notice" do
          subject.filter(event)
          expect(event.get(syslog_severity_name_field)).to eq("notice")
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          expect(event.get(syslog_facility_name_field)).to eq("local4")
        end
      end

      context "when a debug messages arrive" do
        let(:syslog_pri) { 191 }

        it "syslog severity is notice" do
          subject.filter(event)
          expect(event.get(syslog_severity_name_field)).to eq("debug")
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          expect(event.get(syslog_facility_name_field)).to eq("local7")
        end
      end

      context "when an alert messages arrive" do
        let(:syslog_pri) { '137' }

        it "syslog severity is notice" do
          subject.filter(event)
          expect(event.get(syslog_severity_name_field)).to eq("alert")
        end

        it "default syslog_facility is user-level" do
          subject.filter(event)
          expect(event.get(syslog_facility_name_field)).to eq("local1")
          expect(event.get(syslog_facility_code_field)).to eq(17)
        end
      end

      context "when malformed messages arrive" do
        context "if syslog priority value is too high" do
          let(:syslog_pri) { 193 }

          before(:each) { subject.filter(event) }

          context "if use_labels is enabled (default)" do
            it "the event is tagged" do
              expect(event.get("tags")).to include("_syslogpriparsefailure")
            end
            it "the facility label isn't set" do
              expect(event.get(syslog_facility_name_field)).to be_nil
            end
            it "the severity label isn't set" do
              expect(event.get(syslog_severity_name_field)).to be_nil
            end
          end

          context "if use_labels is disabled" do
            let(:options) { super().merge("use_labels" => false) }
            it "the event is not tagged" do
              expect(event.get("tags")).to be_nil
            end
          end

          it "the facility code is still set" do
            expect(event.get(syslog_facility_code_field)).to eq(24)
          end
          it "the severity code is still set" do
            expect(event.get(syslog_severity_code_field)).to eq(1)
          end
        end
      end
    end
  end
end
