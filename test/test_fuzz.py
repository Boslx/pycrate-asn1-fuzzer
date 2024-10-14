import itertools

from pycrate_asn1dir import ITS_CAM_2, ITS_DENM_3
from pycrate_asn1dir.ITS_IS import MAPEM_PDU_Descriptions, SPATEM_PDU_Descriptions, \
    SREM_PDU_Descriptions, SSEM_PDU_Descriptions


def apply_recursive_expansion(asn1_structure, num_expansions=1):
    """
    Recursively expands the ASN.1 structure to generate complex data.

    Args:
      asn1_structure: The ASN.1 structure to expand.
      num_expansions: The number of times to recursively expand the structure.
    """
    ident_history_guided = {}
    asn1_prototype = asn1_structure.get_proto(ident_history=ident_history_guided)
    for _ in itertools.repeat(None, num_expansions):
        asn1_prototype.expand_once(ident_history_guided)
    asn1_prototype.remove_expandable()
    return asn1_prototype


def generate_and_save_fuzzed_data(asn1_structure, asn1_proto, max_samples=10):
    """
    Generates fuzzed data from the ASN.1 proto and saves it.

    Args:
      asn1_structure: The original ASN.1 structure.
      asn1_proto: The expanded ASN.1 prototype for fuzzing.
      max_samples: The maximum number of fuzzed samples to generate.
    """
    for _ in range(max_samples):
        # You are able to control the fuzzing process using coverage_aware and the allowlist
        fuzzed_data = asn1_proto.fuzz(coverage_aware=False)
        asn1_structure.set_val(fuzzed_data)
        print(asn1_structure.to_uper())


def fuzz_asn1_structures(structures, num_expansions=1, max_samples=200):
    """
    Fuzzes a list of ASN.1 structures.

    Args:
      structures: A list of ASN.1 structures to fuzz.
      num_expansions: The number of times to recursively expand each structure.
      max_samples: The maximum number of fuzzed samples to generate per structure.
    """
    for structure in structures:
        prototype = apply_recursive_expansion(structure, num_expansions)
        generate_and_save_fuzzed_data(structure, prototype, max_samples)


def main():
    asn1_structures = [
        ITS_CAM_2.CAM_PDU_Descriptions.CAM,
        ITS_DENM_3.DENM_PDU_Descriptions.DENM,
        MAPEM_PDU_Descriptions.MAPEM,
        SPATEM_PDU_Descriptions.SPATEM,
        SREM_PDU_Descriptions.SREM,
        SSEM_PDU_Descriptions.SSEM,
    ]
    fuzz_asn1_structures(asn1_structures)


if __name__ == "__main__":
    main()
