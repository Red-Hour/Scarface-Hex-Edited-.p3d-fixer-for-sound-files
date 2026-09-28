py validate_p3d.py Extended.p3d                  # check only
py validate_p3d.py Extended.p3d --fix            # writes Extended_fixed.p3d
py validate_p3d.py Extended.p3d --fix --new-ids  # also gives duplicated IDs new values
py validate_p3d.py Extended.p3d --fix -o out.p3d # pick the output name
