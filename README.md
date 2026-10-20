## HAProxy cloud storage authentication filter (cloudauth)

The cloudauth filter lets HAProxy authenticate the requests it sends to cloud
object storages: Azure Blob Storage, Google Cloud Storage and S3 compatible
storages. The credentials are given by the administrator (environment, file
read at parse time, CLI) or fetched by HAProxy itself from the usual sources of
each cloud, refreshed in the background and never logged.

The filter is built as an addon outside the HAProxy source tree, without any
change to HAProxy itself.

**Status: work in progress.** The filter was first written inside the HAProxy
source tree and is being turned into an addon; it does not build yet.
