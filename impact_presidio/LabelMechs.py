from os.path import basename, isdir
from pathlib import Path
from re import search as re_search
from xattr import xattr
from yaml import safe_load, YAMLError

from impact_presidio.Logging import LOG

_label_mech_fn = None
_project_path = None
_safelabels_filename = '.safelabels'
_xattr_label_base = 'user.us.cyberimpact.SAFE.SCID'


def SafeLabelsFileCheck(path, dataset_SCID):
    LOG.debug(f'_project_path is: {_project_path}')
    LOG.debug(f'_project_path.parent is: {_project_path.parent}')

    if basename(path) == _safelabels_filename:
        LOG.debug(f'Ignoring SafeLabels file {_safelabels_filename}')
        return False

    cur_path = Path(path)
    if not isdir(cur_path):
        cur_path = cur_path.parent

    while cur_path != _project_path.parent:
        LOG.debug(f'cur_path is: {cur_path}')
        safeLabels = None
        try:
            with open((cur_path / _safelabels_filename), 'r') as sl:
                safeLabels = safe_load(sl)
        except EnvironmentError:
            # Couldn't find labels file in this directory, so
            # continue loop one level up.
            cur_path = cur_path.parent
            continue
        except YAMLError as ye:
            # OK. This is bad news.
            #
            # The admin *clearly* had an intended set of controls, but
            # apparently failed to write the YAML correctly.
            #
            # Spit out a warning and exception (to aid in debugging),
            # then refuse access (rather than walking up the directory tree
            # to check the parent's policy, which the admin may well have
            # been trying to supersede with the mis-written file.
            LOG.error('Encountered error while parsing SafeLabels file!')
            LOG.error('Error message:')
            LOG.error(ye)
            LOG.error(f'Failing safe, and disallowing access to: {path}')
            return False

        # Proceeding under the assumption that the safelabels file
        # loaded properly.
        file_version = safeLabels.get('version')
        if file_version is None:
            LOG.warning('SafeLabels file missing \'version\' specifier.')
            LOG.warning('Will attempt to check according to the most recent')
            LOG.warning('version specification...')
        elif file_version == 1.0:
            # Base case, since we have only one version, right now.
            pass
        else:
            # Sigh. Specified an invalid version.
            # Try to parse using the most recent version,
            # and let the chips fall where they may.
            LOG.warning(('SafeLabels file found with invalid ' +
                         '\'version\' specified.'))
            LOG.warning('Will attempt to check according to the most recent')
            LOG.warning('version specification...')
        label_check = SafeLabelsChecker_v1(path, dataset_SCID, safeLabels)
        if label_check:
            LOG.debug(f'Matching SCID found for {path}')
            return True
        else:
            break
    LOG.debug(f'No matching SCIDs found for {path}')
    return False


def SafeLabelsChecker_v1(path, dataset_SCID, safeLabels):
    per_file_overrides = safeLabels.get('overrides')
    if per_file_overrides is None:
        # Not specified; perfectly valid.
        pass
    elif type(per_file_overrides) is not dict:
        # Gotta fail safe again...
        LOG.warning('\'overrides\' specified, but not a dictionary.')
        LOG.warning('Failing safe...')
        return False
    else:
        keys = per_file_overrides.keys()
        labels = None
        for key in keys:
            if re_search(key, path):
                labels = per_file_overrides.get(key)
                break
        if labels is None:
            return False
        if type(labels) is str:
            return (labels == dataset_SCID)
        elif type(labels) is list:
            for label in labels:
                if (label == dataset_SCID):
                    return True
            return False
        else:
            LOG.warning('Incorrectly specified value in \'overrides\' entry.')
            LOG.warning('Failing safe...')
            return False

    default_labels = safeLabels.get('default')
    if default_labels is None:
        LOG.warning('\'default\' entry unspecified!')
        LOG.warning('Failing safe...')
        return False
    elif type(default_labels) is str:
        return (default_labels == dataset_SCID)
    elif type(default_labels) is list:
        for label in default_labels:
            if (label == dataset_SCID):
                return True
        return False
    else:
        LOG.warning('\'default\' specified, but not a valid value.')
        LOG.warning('Failing safe...')
        return False

    # Tack a final false return at the end, to be defensive.
    return False


def ExtendedAttributeLabelCheck(path, dataset_SCID):
    cur_path = Path(path)
    LOG.debug(f'_project_path is: {_project_path}')
    LOG.debug(f'_project_path.parent is: {_project_path.parent}')
    while cur_path != _project_path.parent:
        LOG.debug(f'cur_path is: {cur_path}')
        path_attrs = xattr(cur_path)
        attr_key_list = [e for e in path_attrs.list()
                         if _xattr_label_base in e]

        for attr in attr_key_list:
            LOG.debug(f'Checking xattr: {attr} for path: {cur_path}')
            if (path_attrs[attr]).decode('utf-8') == dataset_SCID:
                LOG.debug(f'Matching SCID found for {path}')
                return True
        cur_path = cur_path.parent
    LOG.debug(f'No matching SCIDs found for {path}')
    return False


def configure_label_mech(presidio_config, project_path):
    global _project_path
    _project_path = Path(project_path)

    global _label_mech_fn
    _label_mech_fn = SafeLabelsFileCheck

    conf_label_mech = presidio_config.get('label_mech')
    if conf_label_mech:
        conf_label_mech = conf_label_mech.lower()
        if conf_label_mech == 'xattr':
            _label_mech_fn = ExtendedAttributeLabelCheck
        elif conf_label_mech != 'safelabels':
            LOG.warning('Unknown value specified for \"label_mech\"')
            LOG.warning('in configuration file.')
    else:
        LOG.warning('\"label_mech\" entry not specified in configuration.')

    if _label_mech_fn == ExtendedAttributeLabelCheck:
        LOG.info('Using extended attribute mechanism for SAFE labels.')
        conf_xattr_label_base = presidio_config.get('xattr_label_base')
        if conf_xattr_label_base:
            _xattr_label_base = conf_xattr_label_base
        LOG.info(f'Extended attribute label base is: {_xattr_label_base}')
    else:
        LOG.info('Using default SafeLabels file mechanism for SAFE labels.')
        conf_safelabels_filename = presidio_config.get('safelabels_filename')
        if conf_safelabels_filename:
            _safelabels_filename = conf_safelabels_filename
        LOG.info(f'SafeLabels file name is: {_safelabels_filename}')


def check_labels(path, dataset_SCID):
    return _label_mech_fn(path, dataset_SCID)
