## 3.2.1
  - Remove spurious leftover text from "use_labels" docs [#15](https://github.com/logstash-plugins/logstash-filter-syslog_pri/pull/15)

## 3.2.0
  - Feat: add tagging on unrecognized `facility_label` code [#11](https://github.com/logstash-plugins/logstash-filter-syslog_pri/pull/11)
  - Change: refactored test code to be streamlined when checking ECS fields [#14](https://github.com/logstash-plugins/logstash-filter-syslog_pri/pull/14)

## 3.1.1
  - Added preview of ECS-v8 support with existing ECS-v1 implementation [#10](https://github.com/logstash-plugins/logstash-filter-syslog_pri/pull/10)

## 3.1.0
  - Feat: ECS compatibility [#9](https://github.com/logstash-plugins/logstash-filter-syslog_pri/pull/9) 

## 3.0.5
  - Update gemspec summary

## 3.0.4
  - Fix some documentation issues

## 3.0.2
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.0.1
  - Republish all the gems under jruby.

## 3.0.0
  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141

## 2.0.4
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.0.3
  - New dependency requirements for logstash-core for the 5.0 release

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
