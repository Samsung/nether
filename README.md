# nether

An application firewall that enforces the "internet"
privileges in Tizen. It uses Cynara as a policy backend
and the NFQUEUE target in netfilter to make decisiions
about outgoing connections and network packets.

The policy backend can be re-implemented by overloading
the NetherPolicyBackend class (there is a simple File based
backend included for testing).

A default policy can be specified in case the policy
backend stops working.


