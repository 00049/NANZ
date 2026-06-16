import dns.resolver
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
resolver.lifetime = 5.0
resolver.timeout = 3.0
print(resolver.resolve("www.bennett.edu.in", "A"))
