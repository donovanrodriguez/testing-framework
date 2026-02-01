from tests import icmpv6_echo

TEST_REGISTRY = {
    "icmpv6_echo": icmpv6_echo,
}


def list_tests():
    return sorted(TEST_REGISTRY.keys())


def get_test(name):
    return TEST_REGISTRY.get(name)
