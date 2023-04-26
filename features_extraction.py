from features import *
import tldextract

def features_extract(url):
    features = []
    features.append(extract_domain(url))
    features.append(number_of_subdomain(url))
    features.append(dns_check(url))
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(http_domain(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))
    features.extend(get_features(url))
    features.append(check_ssl_certificate(url))
    features.append(domain_age(url))
    domain = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
    features.append(domain_end(domain))
    features.append(check_unusual_characters(url))
    features.append(has_javascript(url))
    features.append(check_source_code(url))
    features.append(has_privacy_policy(url))
    return features






