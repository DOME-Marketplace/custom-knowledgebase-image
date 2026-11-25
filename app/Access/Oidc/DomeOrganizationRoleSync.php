<?php

namespace BookStack\Access\Oidc;

use BookStack\Users\Models\Role;
use BookStack\Users\Models\User;
use Illuminate\Support\Facades\DB;

class DomeOrganizationRoleSync
{
    /**
     * @return array{public: int, editor: int, member: bool}|null
     * @throws OidcException
     */
    public function prepare(OidcIdToken $token): ?array
    {
        if (!config('oidc.dome_role_sync.enabled')) {
            return null;
        }

        if (config('oidc.user_to_groups') !== false) {
            throw new OidcException('DOME role sync cannot be combined with OIDC group sync.');
        }

        $editorRoleId = config('oidc.dome_role_sync.editor_role_id');
        if ((!is_string($editorRoleId) && !is_int($editorRoleId)) || !ctype_digit((string) $editorRoleId) || (int) $editorRoleId < 1) {
            throw new OidcException('DOME role sync requires a valid Editor role ID.');
        }

        $publicRole = Role::getSystemRole('public');
        $editorRole = Role::query()->find((int) $editorRoleId);
        if (!$publicRole || !$editorRole || ($editorRole->system_name !== null && $editorRole->system_name !== '')) {
            throw new OidcException('DOME role sync requires an existing non-system Editor role and the Public role.');
        }

        $defaultRoleId = (int) setting('registration-role');
        if ($defaultRoleId !== 0 && $defaultRoleId !== $publicRole->id) {
            throw new OidcException('DOME role sync requires the default registration role to be Public or none.');
        }

        return [
            'public' => $publicRole->id,
            'editor' => $editorRole->id,
            'member' => $this->hasDomeOrganizationPower($token),
        ];
    }

    private function hasDomeOrganizationPower(OidcIdToken $token): bool
    {
        $powers = $token->getSignedClaim('power');
        if (!is_array($powers)) {
            throw new OidcException('DOME role sync requires a valid power list in the ID token.');
        }

        $matches = false;
        foreach ($powers as $power) {
            $type = is_object($power) ? ($power->type ?? null) : null;
            $domain = is_object($power) ? ($power->domain ?? null) : null;
            if (!is_string($type) || trim($type) === '' || !is_string($domain) || trim($domain) === '') {
                throw new OidcException('DOME role sync requires a valid type and domain for each power in the ID token.');
            }

            $matches = $matches || ($type === 'organization' && $domain === 'DOME');
        }

        return $matches;
    }

    /**
     * @param array{public: int, editor: int, member: bool} $assignment
     */
    public function sync(User $user, array $assignment): void
    {
        DB::transaction(function () use ($user, $assignment) {
            $roles = [$assignment['public']];
            if ($assignment['member']) {
                $roles[] = $assignment['editor'];
            }

            $user->roles()->syncWithoutDetaching($roles);
            if (!$assignment['member']) {
                $user->roles()->detach($assignment['editor']);
            }
        });
        $user->unsetRelation('roles');
        $user->clearPermissionCache();
    }
}
