# Introduction

MongoDB is a high-performance, open source, schema-free document-oriented
data store that's easy to deploy, manage and use.
It's network accessible, written in C++ and offers the following features:

- Collection oriented storage - easy storage of object-style data
- Full index support, including on inner objects
- Query profiling
- Replication and fail-over support
- Efficient storage of binary data including large objects (e.g. videos)
- Auto-sharding for cloud-level scalability (Q209) High performance,
  scalability, and  reasonable depth of functionality are the goals for
  the project.  This is a metapackage that depends on all the mongodb parts.


# Review the configurable options

The MongoDB charm allows for certain values to be configurable via the config.yaml file.

A sample of the default settings of the config.yaml file at the time of writing are as follows:

    options:
      dbpath:
        default: "/var/lib/mongodb"
        type: string
        description: The path where the data files will be kept.
      logpath:
        default: "/var/log/mongodb/mongodb.log"
        type: string
        description: The path where to send log data.
      logappend:
        default: True
        type: boolean
        description: Append log entries to existing log file
      bind_ip:
        default: "all"
        type: string
        description: IP address that mongodb should listen for connections.
      port:
        default: 27017
        type: int
        description: Default MongoDB port
      journal:
        default: True
        type: boolean
        description: Enable journaling, http://www.mongodb.org/display/DOCS/Journaling
      cpu:
        default: False
        type: boolean
        description: Enables periodic logging of CPU utilization and I/O wait
      auth:
        default: False
        type: boolean
        description: Turn on/off security
      verbose:
        default: False
        type: boolean
        description: Verbose logging output
      objcheck:
        default: False
        type: boolean
        description: Inspect all client data for validity on receipt (useful for developing drivers)
      quota:
        default: False
        type: boolean
        description: Enable db quota management
      diaglog:
        default: 0
        type: int
        description: Set oplogging level where n is 0=off (default), 1=W, 2=R, 3=both, 7=W+some reads
      nocursors:
        default: False
        type: boolean
        description: Diagnostic/debugging option
      nohints:
        default: False
        type: boolean
        description: Ignore query hints
      noscripting:
        default: False
        type: boolean
        description: Turns off server-side scripting.  This will result in greatly limited functionality
      notablescan:
        default: False
        type: boolean
        description: Turns off table scans.  Any query that would do a table scan fails
      noprealloc:
        default: False
        type: boolean
        description: Disable data file preallocation
      nssize:
        default: "default"
        type: string
        description: Specify .ns file size for new databases
      mms-token:
        default: "disabled"
        type: string
        description: Accout token for Mongo monitoring server
      mms-name:
        default: "disabled"
        type: string
        description: Server name for Mongo monitoring server
      mms-interval:
        default: "disabled"
        type: string
        description: Ping interval for Mongo monitoring server ( in number of seconds )
      autoresync:
        default: False
        type: boolean
        description: Automatically resync if slave data is stale
      oplogSize:
        default: "default"
        type: string
        description: Custom size for replication operation log
      opIdMem:
        default: "default"
        type: string
        description: Size limit for in-memory storage of op ids
      replicaset:
        default: myset
        type: string
        description: Name of the replica set
      web_admin_ui:
        default: True
        type: boolean
        description: Replica Set Admin UI ( accessible via default_port + 1000 )
      replicaset_master:
        default: auto
        type: string
        description: Replica Set master ( optional ). Possible values are 'auto' for automatic detection based on install time or 'host:port' to connect to 'host' on 'port' and register as a member.
      master:
        default: "self"
        type: string
        description: Who is the master DB.  If not "self", put the Master DB here as "host:port"
      config_server_port:
        default: 27019
        type: int
        description: Port number to use for the config-server
      config_server_dbpath:
        default: "/mnt/var/lib/mongodb/configsvr"
        type: string
        description: The path where the config server data files will be kept.
      config_server_logpath:
        default: "/mnt/var/log/mongodb/configsvr.log"
        type: string
        description: The path where to send config server log data.
      arbiter:
        default: "disabled"
        type: string
        description: Enable arbiter mode. Possible values are 'disabled' for no arbiter, 'enable' to become an arbiter or 'host:port' to declare another host as an arbiter.  replicaset_master must be set for this option to work.
      mongos_logpath:
        default: "/mnt/var/log/mongodb/mongos.log"
        type: string
        description: The path where to send log data from the mongo router.
      mongos_port:
        default: 27021
        type: int
        description: Port number to use for the mongo router
      extra_config_options:
        default: "none"
        type: string
        description: Extra options ( comma separated ) to be included ( at the end ) in the mongodb.conf file.
      extra_daemon_options:
        default: "none"
        type: string
        description: Extra options ( exactly as you would type them in the command line ) to be added via the command line to the mongodb daemon
      backups_enabled:
        default: False
        type: boolean
        description: Enable daily backups to disk.
      backup_directory:
        default: "/home/ubuntu/backups"
        type: string
        description: Where can the backups be found.
      backup_copies_kept:
        default: 7
        type: int
        description: Number of backups to keep. Keeps one week's worth by default.

### Where:

- replicaset
   - ie: myreplicaset
   - Each replicaset has a unique name to distinguish it’s members from other replicasets available in the network.
   - The default value of myset should be fine for most single cluster scenarios.

- web_admin_ui
   - MongoDB comes with a basic but very informative web user interface that provides health
     and status information on the database node as well as the cluster.
   - The default value of yes will start the Admin web UI on port 28017.

- replicaset_master
   - If this node is going to be joining an existing replicaset, you can specify a member of that cluster
     ( preferably the master node ) so we can join the existing replicaset.
   - The value should be in the form of host[:port]
   - ie:  hostname ( will connect to hostname on the default port of 27017 )
   - ie:  hostname:port  ( will connect to hostname on port number <port> )

Most of the options in config.yaml have been modeled after the default configuration file for mongodb (normally in /etc/mongodb.conf) and should be familiar to most mongodb admins.  Each option in this charm have a brief description of what it does.


# Deployment

## Single Node


Deploy the first MongoDB instance

    juju deploy mongodb
    juju expose mongodb

## Replica Sets

Deploy the first MongoDB instance

    juju deploy mongodb
    juju expose mongodb

Your deployment should look similar to this ( juju status ):

    machines:
     0:
            dns-name: ec2-50-19-46-207.compute-1.amazonaws.com
            instance-id: i-3817fc5a
            instance-state: running
            state: running
     1:
            dns-name: ec2-50-17-73-255.compute-1.amazonaws.com
            instance-id: i-90c822f2
            instance-state: running
            state: running
    services:
     mongodb:
            charm: local:oneiric/mongodb-17
            exposed: true
            relations:
             replica-set: mongodb
            units:
             mongodb/0:
               machine: 1
               open-ports:
               - 27017/tcp
               - 28017/tcp
               public-address: ec2-50-17-73-255.compute-1.amazonaws.com
               relations:
                 replica-set:
                   state: up
               state: started

In addition, the MongoDB web interface should also be accessible via the services’
public-address and port 28017 ( ie: http://ec2-50-17-73-255.compute-1.amazonaws.com:28017 ).

### (Optional)Change the replicaset name

    juju set mongodb replicaset=<new_replicaset_name>

### Add one more nodes to your replicaset

    juju add-unit mongodb


### Add multiple nodes to your replicaset

    juju add-unit mongodb -n5


We now have a working MongoDB replica-set.


## Sharding

According the the mongodb documentation found on their website (http://docs.mongodb.org/manual/tutorial/deploy-shard-cluster/), one way of deploying a Shard Cluster is as follows:

- deploy config servers
- deploy a mongo shell (mongos)
- deploy shards
- connect the config servers to the mongo shell
- add the shards to the mongo shell


Using Juju we can deploy a sharded cluster using the following commands:

### Prepare a configuration file similar to the following:
    shard1:
      replicaset: shard1
    shard2:
      replicaset: shard2
    shard3:
      replicaset: shard3
    configsvr:
      replicaset: configsvr
We'll save this one as ~/mongodb-shard.yaml
  

### Bootstrap the environment
    juju bootstrap

### Config Servers ( we'll deploy 3 of them )
    juju deploy mongodb configsvr --config ~/mongodb-shard.yaml -n3

### Mongo Shell ( We just deploy one for now )
    juju deploy mongodb mongos

### Shards ( We'll deploy three replica-sets )
    juju deploy mongodb shard1 --config ~/mongodb-shard.yaml -n3
    juju deploy mongodb shard2 --config ~/mongodb-shard.yaml -n3
    juju deploy mongodb shard3 --config ~/mongodb-shard.yaml -n3

### Connect the Config Servers to the Mongo shell (mongos)
    juju add-relation mongos:mongos-cfg configsvr:configsvr

### Connect each Shard to the Mongo shell (mongos)
    juju add-realtion mongos:mongos shard1:database
    juju add-realtion mongos:mongos shard2:database
    juju add-realtion mongos:mongos shard3:database

With the above commands, we should now have a three replica-set sharded cluster running.
Using the default configuration, here are some details of our sharded cluster:
- mongos is running on port 27021
- configsvr is running on port 27019
- the shards are running on the default mongodb port of 27017
- The web admin is turned on by default and accessible with your browser on port 28017 on each of the shards.

To verify that your sharded cluster is running, connect to the mongo shell and run sh.status():
- mongo --host <mongos_host>:<mongos_port>
- run sh.status()
You should see your the hosts for your shards in the status output.

## Backups

Backups can be enabled via config. Note that destroying the service cannot
currently remove the backup cron job so it will continue to run. There is a
setting for the number of backups to keep, however, to prevent from filling
disk space.

To fetch the backups scp the files down from the path in the config.


# Troubleshooting

- If your master/slave/replicaset deployment is not updating correctly, check the log files at /var/log/mongodb/mongodb.log to see if there is an obvious reason ( port not open etc.).
- Ensure that TCP port 27017 is accessible from all of the nodes in the deployment.
- If you are trying to access your MongoDB instance from outside your deployment, ensure that the service has been exposed ( juju expose mongodb )
- Make sure that the mongod process is running ( ps -ef | grep mongo ).
- Try restarting the database ( restart mongodb )
- If all else fails, remove the data directory on the slave ( rm -fr /var/log/mongodb/data/* ) and restart the mongodb-slave daemon ( restart mongodb ).
- The MongoDB website ( http://www.mongodb.org ) has a very good documentation section ( http://www.mongodb.org/display/DOCS/Home )


