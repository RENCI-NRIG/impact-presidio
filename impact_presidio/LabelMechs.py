import os.path
import re
import xattr
import yaml

from pathlib import Path


_label_mech_fn = None
_project_path = None
_safelabels_filename = '.safelabels'
_xattr_label_base = 'user.us.cyberimpact.SAFE.SCID'


def SafeLabelsFileCheck(path, dataset_SCID):
    if os.path.basename(path) == _safelabels_filename:
        print('Ignoring SafeLabels file %s' % _safelabels_filename)
        return False

    cur_path = Path(path)
    if not os.path.isdir(cur_path):
        cur_path = cur_path.parent

    while cur_path != _project_path.parent:
        safeLabels = None
        try:
            with open((cur_path / _safelabels_filename), 'r') as sl:
                safeLabels = yaml.safe_load(sl)
        except EnvironmentError:
            # Couldn't find labels file in this directory, so
            # continue loop one level up.
            cur_path = cur_path.parent
            continue
        except yaml.YAMLError as ye:
            # OK. This is bad news.
            #
            # The admin *clearly* had an intented set of controls, but
            # apparently failed to write the YAML correctly.
            #
            # Spit out a warning and exception (to aid in debugging),
            # then refuse access (rather than walking up the directory tree
            # to check the parent's policy, which the admin may well have
            # been trying to supersede with the mis-written file.
            print('Encountered error while parsing SafeLabels file!')
            print('Backtrace follows:')
            print(ye)
            print('Failing safe, and disallowing access to: %s' %
                  path)
            return False

        # Proceeding under the assumption that the safelabels file
        # loaded properly.
        file_version = safeLabels.get('version')
        if file_version is None:
            print('SafeLabels file missing \'version\' specifier.')
            print('Will attempt to check according to the most recent')
            print('version specification...')
        elif file_version == 1.0:
            # Base case, since we have only one version, right now.
            pass
        else:
            # Sigh. Specified an invalid version.
            # Try to parse using the most recent version,
            # and let the chips fall where they may.
            print('SafeLabels file found with invalid \'version\' specified.')
            print('Will attempt to check according to the most recent')
            print('version specification...')
        label_check = SafeLabelsChecker_v1(path, dataset_SCID, safeLabels)
        if label_check:
            print('Granting access to %s' % path)
            return True
        else:
            break
    print('Refusing access to %s' % path)
    return False


def SafeLabelsChecker_v1(path, dataset_SCID, safeLabels):
    per_file_overrides = safeLabels.get('overrides')
    if per_file_overrides is None:
        # Not specified; perfectly valid.
        pass
    elif type(per_file_overrides) is not dict:
        # Gotta fail safe again...
        print('\'overrides\' specified, but not a dictionary.')
        print('Failing safe...')
        return False
    else:
        keys = per_file_overrides.keys()
        filename = os.path.basename(path)
        labels = None
        for key in keys:
            rx = re.compile(key)
            if rx.search(filename):
                labels = per_file_overrides.get(key)
                break
        if type(labels) is str:
            return (labels == dataset_SCID)
        elif type(labels) is list:
            for l in labels:
                if (l == dataset_SCID):
                    return True
            return False

    default_labels = safeLabels.get('default')
    if default_labels is None:
        print('\'default\' entry unspecified!')
        print('Failing safe...')
        return False
    elif type(default_labels) is str:
        return (default_labels == dataset_SCID)
    elif type(default_labels) is list:
        for l in default_labels:
            if (l == dataset_SCID):
                return True
        return False
    else:
        print('\'default\' specified, but not a valid value.')
        print('Failing safe...')
        return False

    # Tack a final false return at the end, to be defensive.
    return False


def ExtendedAttributeLabelCheck(path, dataset_SCID):
    cur_path = Path(path)
    # print('_project_path is: %s' % _project_path)
    # print('_project_path.parent is: %s' % _project_path.parent)
    while cur_path != _project_path.parent:
        # print('cur_path is: %s' % cur_path)
        path_attrs = xattr.xattr(cur_path)
        attr_key_list = [e for e in path_attrs.list()
                         if _xattr_label_base in e]

        for attr in attr_key_list:
            print('Checking attr: %s for path: %s' % (attr, cur_path))
            if (path_attrs[attr]).decode('utf-8') == dataset_SCID:
                print('Granting access to %s' % path)
                return True
        cur_path = cur_path.parent
    print('Refusing access to %s' % path)
    return False


def configure_label_mech(label_mech, presidio_config, project_path):
    global _project_path
    _project_path = Path(project_path)

    global _label_mech_fn
    _label_mech_fn = SafeLabelsFileCheck
    if label_mech:
        label_mech = label_mech.lower()
        if label_mech == 'xattr':
            _label_mech_fn = ExtendedAttributeLabelCheck
        elif label_mech != 'safelabels':
            print('Unknown value specified for \"label_mech\"')
            print('in configuration file.')
    else:
        print('\"label_mech\" entry not specified in configuration.')

    if _label_mech_fn == ExtendedAttributeLabelCheck:
        print('Using extended attribute mechanism for SAFE labels.')
        conf_xattr_label_base = presidio_config.get('xattr_label_base')
        if conf_xattr_label_base:
            _xattr_label_base = conf_xattr_label_base
        print('Extended attribute label base is: %s' % _xattr_label_base)
    else:
        print('Using default SafeLabels file mechanism for SAFE labels.')
        conf_safelabels_filename = presidio_config.get('safelabels_filename')
        if conf_safelabels_filename:
            _safelabels_filename = conf_safelabels_filename
        print('SafeLabels file name is: %s' % _safelabels_filename)


def check_labels(path, dataset_SCID):
    return _label_mech_fn(path, dataset_SCID)
