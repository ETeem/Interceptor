# Interceptor

## Introduction
The email interceptor application is an Email To Splunk Gateway that can also forward emails. The purpose of this application is to accept emails, and then based on the subject (configurable)
of the email, determines if the email will be forwarded to the email server, or written to a text file on disk for the Splunk forwarder to forward to splunk.  Other options (Sendmail / Postfix)
have been evaluated for this purpose and between the level of complication for configuration of this particular need and the speed at which is can process incoming requests, it was necessary to
create a tool to handle this in a more performant manner.  Postfix and Sendmail both can inspect envelope information, but not message content, which precludes them from doing this by subject
(though, they could by sender/receiver).

## Command Line Usage
### Config File
The Config file is /etc/interceptor.yaml and is in YAML Format. This is a simple config file that contains how to send the emails to Splunk, the ports Splunk is listening on for that index,
the subject to send to Splunk (instead of forwarding), and some other simple information.  An Example config file is provided.

### Reloading The Config
The Interceptor system was built to be always up (it was also built to be containerized in a Swarm cluster if desired).  As such, there is no need to stop/start/restart the application. If a manual
change is made to /etc/interceptor.yaml, a SIGUSR1 message can be sent to tell the application to reload the config file.  Example:
```
kill -SIGUSR1 <pid_of_interceptor>
```

### Writing The Config File
The Interceptor system can write the current running configuration to disk.  A SIGUSR2 can be sent to the application to inform it to re-write the /etc/interceptor.yaml file from the current list of subjects.
Example:
```
kill -SIGUSR2 <pid_of_interceptor>
```

