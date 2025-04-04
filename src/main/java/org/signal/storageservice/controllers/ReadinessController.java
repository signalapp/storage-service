package org.signal.storageservice.controllers;

import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.models.Query;
import com.google.cloud.bigtable.data.v2.models.TableId;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@Path("_ready")
public class ReadinessController {

  private final BigtableDataClient client;
  private final Set<TableId> tableIds;
  private final AtomicInteger clientWarmups;

  public ReadinessController(final BigtableDataClient client, final Set<String> tableIds, final int clientWarmups) {
    this.client = client;
    this.tableIds = tableIds.stream()
        .map(TableId::of)
        .collect(Collectors.toSet());
    this.clientWarmups = new AtomicInteger(clientWarmups);
  }

  @GET
  public String isReady() {

    if (clientWarmups.getAndDecrement() > 0) {
      // The first few times this is called, run some warm-up queries.
      // Note: unless one of these queries throws an unchecked exception, this will still invariably return a 200,
      // meaning the instance may be put in service before all warmups have run, depending on the load balancer
      // configuration.
      tableIds.forEach(tableId -> client.readRows(Query.create(tableId).limit(1)).stream().findAny());
    }

    return "ready";
  }
}
