# Spooling & destination reachability

How long mail waits for a destination that is down, and what you see while it waits. Under Mail, next to the queue. The
defaults are the usual Postfix values.

## Settings

- **Queue lifetime** (`maximal_queue_lifetime`) and **bounce lifetime** (`bounce_queue_lifetime`): how long a mail is kept
  before it bounces back to the sender. Default 5 days. `spool-set`.
- Per receiving server eFa-next shows **reachable since** or **unreachable since**, read from the Postfix log.
- An **alarm** when a destination goes down and again when it returns.
- After a server returns, delivery is **staggered**: Postfix starts with a few connections and raises them while delivery
  works, so a recovered server is not flooded.

Nothing is lost: a mail that cannot be delivered stays in the queue until its lifetime ends.
