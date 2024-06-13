package io.mosip.kernel.lkeymanager.entity;

import java.time.LocalDateTime;

import jakarta.persistence.AttributeOverride;
import jakarta.persistence.AttributeOverrides;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinColumns;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import io.mosip.kernel.lkeymanager.entity.id.LicenseKeyPermissionID;
import lombok.Data;

/**
 * Entity class for License key permissions.
 * 
 * @author Sagar Mahapatra
 * @since 1.0.0
 *
 */
@Data
@Entity
@IdClass(LicenseKeyPermissionID.class)
@Table(name = "licensekey_permission")
public class LicenseKeyPermission {
	/**
	 * Composite Primary ID : License Key & Permission.
	 */
	@Id
	@AttributeOverrides({
			@AttributeOverride(name = "license_key", column = @Column(name = "license_key", nullable = false, length = 255)),
			@AttributeOverride(name = "permission", column = @Column(name = "permission", nullable = false, length = 512)) })
	private String licenseKey;
	
	private String permission;
	/**
	 * The active state of permission.
	 */
	@Column(name = "is_active", nullable = false)
	private boolean isActive;
	/**
	 * The permission created by.
	 */
	@Column(name = "cr_by", nullable = false, length = 256)
	private String createdBy;
	/**
	 * The permission created at.
	 */
	@Column(name = "cr_dtimes", nullable = false)
	private LocalDateTime createdDateTimes;
	/**
	 * The permission updated by.
	 */
	@Column(name = "upd_by", length = 256)
	private String updatedBy;
	/**
	 * The permission updated at.
	 */
	@Column(name = "upd_dtimes")
	private LocalDateTime updatedDateTimes;
	/**
	 * The deletion state of permission.
	 */
	@Column(name = "is_deleted")
	private boolean isDeleted;
	/**
	 * The permission deleted at.
	 */
	@Column(name = "del_dtimes")
	private LocalDateTime deletedDateTimes;

	/**
	 * Many to One mapping.
	 */
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumns({
			@JoinColumn(name = "license_key", referencedColumnName = "license_key", insertable = false, updatable = false), })
	private LicenseKeyList licenseKeyListReference;
}
